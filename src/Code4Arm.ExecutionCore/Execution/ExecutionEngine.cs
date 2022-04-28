// ExecutionEngine.cs
// Author: Ondřej Ondryáš

using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Dwarf;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Code4Arm.ExecutionCore.Protocol.Events;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.Unicorn;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Constants;
using MediatR;
using Microsoft.Extensions.Logging;
using Architecture = Code4Arm.Unicorn.Abstractions.Enums.Architecture;

namespace Code4Arm.ExecutionCore.Execution;

public class ExecutionEngine : IExecutionEngine, IRuntimeInfo
{
    private record AddressBreakpoint : Breakpoint
    {
        public uint Address { get; init; }
    }

    private enum UnexpectedStopCause
    {
        Normal,
        StrictAccessHook,
        TrampolineUnbound,
        TimeoutOrExternalCancellation
    }

    private const int MaxArrayPoolSize = 2 * 1024 * 1024;
    private const int MaxStackAllocatedSize = 512;

    internal readonly MemoryStream InputMemoryStream;
    internal readonly MemoryStream OutputMemoryStream;

    private UnexpectedStopCause _lastStopCause = UnexpectedStopCause.Normal;
    private MemoryAccessType _disallowedStrictAccessType;

    private readonly Guid _executionId;
    private readonly ILogger<ExecutionEngine> _logger;
    private readonly ILogger<ExecutionEngine> _clientLogger;
    private Executable? _exe;
    private List<MemorySegment>? _segments;
    private MemorySegment? _stackSegment;
    private ExecutionOptions _options;
    private readonly IMediator _mediator;
    private Random _rnd = new();
    private readonly ArrayPool<byte> _arrayPool;
    private List<UnicornHookRegistration> _strictAccessHooks = new();
    private CancellationTokenSource? _currentCts;
    private uint _pc;
    private UnicornHookRegistration _trampolineHookRegistration;
    private bool _firstRun = true;
    private DwarfLineAddressResolver? _lineResolver;
    private DebugProvider? _debugProvider;

    private SemaphoreSlim _runSemaphore = new(1);

    private readonly Dictionary<uint, AddressBreakpoint> _currentBreakpoints = new();

    public StepBackMode StepBackMode { get; set; }
    public bool EnableStepBackMemoryCapture { get; set; }
    public bool EnableRegisterDataBreakpoints { get; set; }

    public ExecutionState State { get; private set; }
    public IExecutableInfo? ExecutableInfo => _exe;
    public IRuntimeInfo? RuntimeInfo => _exe == null ? null : this;
    public IDebugProvider? DebugProvider => _debugProvider;

    public uint StackStartAddress { get; private set; }
    public uint StackSize => _options.StackSize;
    public uint StackTopAddress { get; private set; }
    public uint StackEndAddress { get; private set; }

    public IReadOnlyList<MemorySegment> Segments =>
        _segments as IReadOnlyList<MemorySegment> ?? ImmutableList<MemorySegment>.Empty;

    public uint ProgramCounter => _pc;

    public IUnicorn Engine { get; }
    public Stream EmulatedInput => InputMemoryStream;
    public Stream EmulatedOutput => OutputMemoryStream;

    public ExecutionEngine(ExecutionOptions options, IMediator mediator,
        ILogger<ExecutionEngine> systemLogger, ILogger<ExecutionEngine> clientLogger)
    {
        _options = options;
        _mediator = mediator;

        Engine = this.MakeUnicorn();
        State = ExecutionState.Unloaded;

        InputMemoryStream = new MemoryStream();
        OutputMemoryStream = new MemoryStream();

        _arrayPool = ArrayPool<byte>.Shared;

        _logger = systemLogger;
        _clientLogger = clientLogger;
        _executionId = Guid.NewGuid();
    }

    private IUnicorn MakeUnicorn()
    {
        var unicorn = new Unicorn.Unicorn(Architecture.Arm, EngineMode.Arm | EngineMode.LittleEndian);
        unicorn.CheckIfBindingMatchesLibrary(true);

        unicorn.CpuModel = Arm.Cpu.MAX;
        unicorn.EnableMultipleExits();

        return unicorn;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [MemberNotNull(nameof(_exe), nameof(_segments), nameof(_debugProvider), nameof(_lineResolver))]
    private void CheckLoaded()
    {
        // Iff the rest of this code works as intended, this could be cut down only to _exe == null
        if (_exe == null || _segments == null || _debugProvider == null || _lineResolver == null)
            throw new InvalidOperationException("Executable not loaded.");
    }

    private void MakeStackSegment()
    {
        if (_segments == null)
            throw new InvalidOperationException("_segments must be initialized.");

        var stOpt = _options.StackPlacementOptions;
        var addressOpts = (int)stOpt & ((int)StackPlacementOptions.FixedAddress +
            (int)StackPlacementOptions.RandomizeAddress + (int)StackPlacementOptions.AlwaysKeepFirstAddress);

        if ((addressOpts & (addressOpts - 1)) != 0) // Has more than one set bit (~ is power of 2)
            throw new InvalidOperationException(
                $"Invalid stack placement options: only one of {StackPlacementOptions.FixedAddress}, {StackPlacementOptions.RandomizeAddress} and {StackPlacementOptions.AlwaysKeepFirstAddress} can be used.");

        uint stackSegmentBegin;

        if (stOpt.HasFlag(StackPlacementOptions.FixedAddress))
        {
            // Forced address (though it will be aligned in ctor anyway)
            stackSegmentBegin = _options.ForcedStackAddress;
        }
        else if (_stackSegment == null || stOpt.HasFlag(StackPlacementOptions.RandomizeAddress))
        {
            // Randomization enabled or no stack has been created yet
            stackSegmentBegin = this.CheckAndRandomizeStackAddress();
        }
        else if (!stOpt.HasFlag(StackPlacementOptions.AlwaysKeepFirstAddress))
        {
            // Randomization disabled and stack has previously been created ~ use it
            // This is the default behaviour ~ stack address is decided upon once 
            stackSegmentBegin = this.CheckAndRandomizeStackAddress(_stackSegment.StartAddress);
        }
        else
        {
            // Dangerous option: always keeps the first assigned address – no collision check is done
            stackSegmentBegin = _stackSegment.StartAddress;
        }

        StackStartAddress = stackSegmentBegin;
        StackEndAddress = stackSegmentBegin + StackSize;
        StackTopAddress = _options.StackPointerType switch
        {
            StackPointerType.FullDescending => StackEndAddress,
            StackPointerType.FullAscending => stackSegmentBegin - 4,
            StackPointerType.EmptyDescending => StackEndAddress - 4,
            StackPointerType.EmptyAscending => stackSegmentBegin,
            _ => throw new ArgumentOutOfRangeException()
        };

        var newStackSegment = new MemorySegment(stackSegmentBegin, StackSize) { IsStack = true };
        _segments.Add(newStackSegment);

        if (_stackSegment == null)
        {
            _stackSegment = newStackSegment;

            Engine.MemMap(_stackSegment.StartAddress, _stackSegment.Size,
                MemoryPermissions.Read | MemoryPermissions.Write);

            if (stOpt.HasFlag(StackPlacementOptions.RandomizeData))
                this.RandomizeMemory(stackSegmentBegin, StackSize);
            else if (stOpt.HasFlag(StackPlacementOptions.ClearData))
                this.ClearMemory(stackSegmentBegin, StackSize);

            return;
        }

        _segments.Remove(_stackSegment);

        var samePlace = _stackSegment.StartAddress == newStackSegment.StartAddress &&
            _stackSegment.EndAddress == newStackSegment.EndAddress;

        if (!samePlace)
        {
            byte[]? keptStackData = null;
            var keptSize = Math.Min(_stackSegment.Size, newStackSegment.Size);
            var rented = keptSize <= MaxArrayPoolSize;

            if (stOpt.HasFlag(StackPlacementOptions.KeepData))
            {
                keptStackData = rented ? _arrayPool.Rent((int)keptSize) : new byte[keptSize];
                Engine.MemRead(_stackSegment.StartAddress, keptStackData, keptSize);
            }

            Engine.MemUnmap(_stackSegment.StartAddress, _stackSegment.Size);
            Engine.MemMap(newStackSegment.StartAddress, newStackSegment.Size,
                MemoryPermissions.Read | MemoryPermissions.Write);

            if (keptStackData != null)
            {
                Engine.MemWrite(stackSegmentBegin, keptStackData, keptSize);

                if (rented)
                    _arrayPool.Return(keptStackData);
            }
        }
        else if (stOpt.HasFlag(StackPlacementOptions.RandomizeData))
        {
            this.RandomizeMemory(stackSegmentBegin, StackSize);
        }
        else if (stOpt.HasFlag(StackPlacementOptions.ClearData))
        {
            this.ClearMemory(stackSegmentBegin, StackSize);
        }

        _stackSegment.Dispose();
        _stackSegment = newStackSegment;
    }

    private uint CheckAndRandomizeStackAddress(long initial = -1)
    {
        uint stackSegmentBegin;
        bool collision;

        do
        {
            collision = false;

            // If there was a starting address, use it first and set it to value other than -1
            // so that it's not used the next time
            stackSegmentBegin = initial == -1
                ? (uint)_rnd.NextInt64(0, uint.MaxValue - StackSize - 4096)
                : (uint)initial;
            initial = 0;

            stackSegmentBegin -= (stackSegmentBegin % 4096);

            if (_segments == null)
                break;

            foreach (var memorySegment in _segments)
            {
                if (memorySegment.ContainsBlock(stackSegmentBegin, StackSize))
                {
                    collision = true;

                    break;
                }
            }
        } while (collision);

        return stackSegmentBegin;
    }

    // CS8774 (member must not be null when method returns) doesn't seem to work very well when MemberNotNull covers
    // a property that always returns a field set by the method to a non-null value.
#pragma warning disable CS8774
    [MemberNotNull(nameof(ExecutableInfo), nameof(RuntimeInfo), nameof(DebugProvider))]
    public Task LoadExecutable(Executable executable)
    {
        if (executable == null)
            throw new ArgumentNullException(nameof(executable));

        _segments ??= new List<MemorySegment>(executable.Segments.Count + 1);

        // This replaces the segment descriptor in _segments and MAPS MEMORY accordingly
        this.MakeStackSegment();

        if (_exe != null)
        {
            this.UnmapAllMemory();
            _firstRun = false;
        }

        _exe = executable;

        _debugProvider = new DebugProvider(this);
        _lineResolver = new DwarfLineAddressResolver(_exe.Elf);

        this.MapMemoryFromExecutable();
        this.InitTrampolineHook();

        State = ExecutionState.Ready;

        return Task.CompletedTask;
    }
#pragma warning restore CS8774

    private void UnmapAllMemory()
    {
        if (_segments == null)
            return;

        foreach (var strictAccessHook in _strictAccessHooks)
        {
            strictAccessHook.RemoveHook();
        }

        foreach (var segment in _segments)
        {
            if (segment.IsStack)
                continue;

            if (segment.IsDirect && segment.DirectHandle != null)
                segment.DirectHandle.DangerousRelease();

            Engine.MemUnmap(segment.StartAddress, segment.Size);
        }

        // TODO?
        _segments?.Clear();
    }

    private void MapMemoryFromExecutable()
    {
        this.CheckLoaded();

        foreach (var segment in _exe.Segments)
        {
            if (segment.IsDirect && segment.DirectHandle != null)
            {
                var refAdded = false;
                segment.DirectHandle.DangerousAddRef(ref refAdded);

                if (!refAdded)
                    throw new Exception("Cannot increase reference counter on a safe handle.");

                Engine.MemMap(segment.StartAddress, segment.Size, segment.Permissions.ToUnicorn(),
                    segment.DirectHandle.DangerousGetHandle());

                _segments.Add(segment);

                continue;
            }

            Engine.MemMap(segment.StartAddress, segment.Size, segment.Permissions.ToUnicorn());
            _segments.Add(segment);

            if (segment.IsTrampoline)
            {
                var jumpBackInstruction = new byte[] { 0x1e, 0xff, 0x2f, 0xe1 };
                var span = jumpBackInstruction.AsSpan();

                for (var address = segment.ContentsStartAddress; address < segment.ContentsEndAddress; address += 4)
                {
                    Engine.MemWrite(address, span);
                }
            }
        }

        if (_options.UseStrictMemoryAccess)
        {
            foreach (var segment in _segments)
            {
                if (segment.StartAddress != segment.ContentsStartAddress)
                {
                    _strictAccessHooks.Add(Engine.AddMemoryHook(this.StrictAccessHook,
                        MemoryHookType.Read | MemoryHookType.Write | MemoryHookType.Fetch,
                        segment.StartAddress, segment.ContentsStartAddress - 1));
                }

                if (segment.EndAddress != segment.ContentsEndAddress)
                {
                    _strictAccessHooks.Add(Engine.AddMemoryHook(this.StrictAccessHook,
                        MemoryHookType.Read | MemoryHookType.Write | MemoryHookType.Fetch,
                        segment.ContentsEndAddress, segment.EndAddress - 1));
                }
            }
        }
    }

    /// <summary>
    /// Registers a hook for the function simulator trampoline memory segment.
    /// Always removes the previous trampoline hook.
    /// If no trampoline memory segment exists, only removes the previous hook.
    /// </summary>
    private void InitTrampolineHook()
    {
        var trampoline = _segments?.FirstOrDefault(s => s.IsTrampoline);

        if (trampoline == null)
        {
            if (_trampolineHookRegistration == default)
                return;
            Engine.RemoveHook(_trampolineHookRegistration);
            _trampolineHookRegistration = default;

            return;
        }

        _trampolineHookRegistration = Engine.AddCodeHook(this.TrampolineHookHandler, trampoline.ContentsStartAddress,
            trampoline.ContentsEndAddress);
    }

    private void TrampolineHookHandler(IUnicorn engine, ulong address, uint size)
    {
        if (_exe is not { FunctionSimulators: { } } ||
            !_exe.FunctionSimulators.TryGetValue((uint)address, out var simulator))
        {
            Engine.EmuStop();

            _logger.LogTrace("Execution {Id}: Trampoline hook on unbound address {Address:x8}.", _executionId, address);
            _clientLogger.LogError(
                "Program attempted to fetch from the function simulator memory segment on address {Address:x8} which is not bound to any simulated function.",
                address);

            _lastStopCause = UnexpectedStopCause.TrampolineUnbound;

            return;
        }

        _pc = (uint)address;
        simulator.FunctionSimulator.Run(this);
    }

    /// <summary>
    /// Load data of segments from the executable.
    /// </summary>
    /// <remarks>
    /// This is used just before emulation is started. It overwrites the current contents of virtual memory with data
    /// from the executable and zeroes out BSS sections.
    /// </remarks>
    public void InitMemoryFromExecutable()
    {
        this.CheckLoaded();

        foreach (var segment in _exe.Segments)
        {
            if (segment.HasData)
            {
                if (_options.RandomizeExtraAllocatedSpaceContents)
                {
                    if (segment.ContentsStartAddress != segment.StartAddress)
                        this.RandomizeMemory(segment.StartAddress, segment.ContentsStartAddress - segment.StartAddress);

                    if (segment.ContentsEndAddress != segment.EndAddress)
                        this.RandomizeMemory(segment.ContentsEndAddress,
                            segment.EndAddress - segment.ContentsEndAddress);
                }

                if (segment.HasBssSection)
                {
                    this.ClearMemory(segment.BssStart, segment.BssEnd - segment.BssStart);
                }

                var data = segment.GetData();
                Engine.MemWrite(segment.ContentsStartAddress, data);
            }
        }
    }

    private void RandomizeMemory(uint start, uint size)
    {
        // The other option is to allocate _size_ bytes worth of memory and do a single write
        // but I prefer this version which takes (much?) more CPU cycles but allocates MaxStackAllocatedSize B max 

        var bufferSize = Math.Min(size, MaxStackAllocatedSize);
        Span<byte> buffer = stackalloc byte[(int)bufferSize];
        var end = start + size;

        for (var address = start; address < end; address += bufferSize)
        {
            _rnd.NextBytes(buffer);
            Engine.MemWrite(address, buffer, Math.Min(bufferSize, end - address));
        }
    }

    private void ClearMemory(uint start, uint size)
    {
        // Same as in RandomizeMemory()

        var bufferSize = Math.Min(size, MaxStackAllocatedSize);
        Span<byte> buffer = stackalloc byte[(int)bufferSize];
        buffer.Clear();
        var end = start + size;

        for (var address = start; address < end; address += bufferSize)
        {
            Engine.MemWrite(address, buffer, Math.Min(bufferSize, end - address));
        }
    }

    private void StrictAccessHook(IUnicorn engine, MemoryAccessType memoryAccessType, ulong address, int size,
        long value)
    {
        _logger.LogTrace("Execution {Id}: virtually unmapped access to memory at {Address:x8}.", _executionId, address);
        Engine.EmuStop();
        _lastStopCause = UnexpectedStopCause.StrictAccessHook;
        _disallowedStrictAccessType = memoryAccessType;
    }

    /// <summary>
    /// Finds a line in a given source on which a breakpoint can be set, starting the search on a given line and going
    /// forward in the file. Returns the local line number and the corresponding address in the executable.
    /// </summary>
    /// <param name="sourceCompilationPath">The compilation path of the source file.</param>
    /// <param name="sourceObject">The source assembled object.</param>
    /// <param name="startingLocalLine">Local number of the line to start the search on.</param>
    /// <returns>A tuple of resulting line and address, or (-1, 0) if no suitable line exists.</returns>
    private (int Line, uint Address) FindClosestBreakablePosition(string sourceCompilationPath,
        AssembledObject sourceObject,
        int startingLocalLine)
    {
        var tryingLine = startingLocalLine;

        // Dwarf lines are numbered from 1
        var address = _lineResolver!.GetAddress(sourceCompilationPath, tryingLine + 1);
        var successful = true;

        while (address == uint.MaxValue && tryingLine < sourceObject.ProgramLines)
        {
            successful = false;
            tryingLine++;

            for (; tryingLine < sourceObject.ProgramLines; tryingLine++)
            {
                if (!sourceObject.IsProgramLine![tryingLine])
                    continue;

                address = _lineResolver!.GetAddress(sourceCompilationPath, tryingLine + 1);
                successful = true;

                break;
            }
        }

        return successful ? (tryingLine, address) : (-1, 0);
    }

    public IEnumerable<Breakpoint> SetBreakpoints(Source file, IEnumerable<SourceBreakpoint> breakpoints)
    {
        this.CheckLoaded();

        var sourceCompilationPath = _exe.GetCompilationPathForSource(file);
        var sourceObject = _exe.GetObjectForSource(file);

        if (sourceObject == null)
        {
            _clientLogger.LogError("Cannot place breakpoint in file {File}.", file.Name);

            return Enumerable.Empty<Breakpoint>();
        }

        _currentBreakpoints.Clear();
        var ret = new List<Breakpoint>();

        foreach (var breakpoint in breakpoints)
        {
            var localLine = _debugProvider.LineFromClient(breakpoint.Line);
            var (targetLine, targetAddress) =
                this.FindClosestBreakablePosition(sourceCompilationPath, sourceObject, localLine);

            if (targetLine == -1)
            {
                // Breakpoint cannot be set on the provided line; return a 'dummy', unverified Breakpoint on this line.
                // Don't create a _currentBreakpoints entry.
                ret.Add(new Breakpoint()
                {
                    Line = breakpoint.Line,
                    Message = "Line does not contain an instruction.",
                    Source = file,
                    Verified = false
                });
            }
            else if (_currentBreakpoints.ContainsKey(targetAddress))
            {
                // Breakpoint on the address is already defined
                ret.Add(new Breakpoint()
                {
                    Line = breakpoint.Line,
                    Message =
                        $"Breakpoint would trigger on line {_debugProvider.LineToClient(targetLine)} that already contains a breakpoint.",
                    Source = file,
                    Verified = false
                });
            }
            else
            {
                // Create a breakpoint with address information and store it in _currentBreakpoints
                var addedBreakpoint = new AddressBreakpoint()
                {
                    Id = targetAddress,
                    Line = _debugProvider.LineToClient(targetLine),
                    Source = file,
                    Verified = true, // TODO: Check if line contains instruction or data? Somehow?
                    InstructionReference = targetAddress.ToString(),
                    Address = targetAddress
                };

                ret.Add(addedBreakpoint);
                _currentBreakpoints.Add(targetAddress, addedBreakpoint);
            }
        }

        this.MakeExits();

        return ret;
    }

    public IEnumerable<Breakpoint> SetDataBreakpoints(IEnumerable<DataBreakpoint> dataBreakpoints)
    {
        throw new NotImplementedException();
    }

    public IEnumerable<Breakpoint> SetExceptionBreakpoints(IEnumerable<string> filterIds)
    {
        throw new NotImplementedException();
    }

    public IEnumerable<Breakpoint> SetFunctionBreakpoints(IEnumerable<FunctionBreakpoint> functionBreakpoints)
    {
        throw new NotImplementedException();
    }

    public IEnumerable<Breakpoint> SetInstructionBreakpoints(IEnumerable<InstructionBreakpoint> instructionBreakpoints)
    {
        throw new NotImplementedException();
    }

    private void MakeExits()
    {
        if (_exe == null)
        {
            Engine.SetExits(ReadOnlySpan<ulong>.Empty, 0);

            return;
        }

        Span<ulong> exits = stackalloc ulong[_currentBreakpoints.Count + 2];

        // Breakpoints
        var i = 0;
        foreach (var (_, breakpoint) in _currentBreakpoints)
        {
            exits[i++] = breakpoint.Address;
        }

        exits[i++] = _exe.LastInstructionAddress + 4;
        exits[i] = _exe.TextSectionEndAddress; // Is this desirable?

        Engine.SetExits(exits);
    }

    private async Task EmulationEnded()
    {
        _logger.LogTrace("Execution {Id}: Ended with PC = {PC:x8}.", _executionId, _pc);
        State = ExecutionState.Finished;

        await this.SendEvent(new ExitedEvent() { ExitCode = 0 });
    }

    private async Task StartEmulation(uint startAddress, ulong count = 0ul)
    {
        try
        {
            _logger.LogTrace("Execution {Id}: Starting on {StartAddress:x8}.", _executionId, startAddress);
            State = ExecutionState.Running;
            _pc = startAddress;
            Engine.EmuStart(startAddress, 0, 0, count);
            _pc = Engine.RegRead<uint>(Arm.Register.PC);

            try
            {
                if (_lastStopCause != UnexpectedStopCause.Normal)
                {
                    await this.HandleStopCause().ConfigureAwait(false);
                    _lastStopCause = UnexpectedStopCause.Normal;
                }
                else if (_currentBreakpoints.TryGetValue(_pc, out var breakpoint))
                {
                    await this.BreakpointHit(breakpoint).ConfigureAwait(false);
                }
                else
                {
                    await this.EmulationEnded().ConfigureAwait(false);
                }
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Execution {Id}: Emulation result handling exception.", _executionId);

                throw;
            }
        }
        catch (UnicornException e)
        {
            _pc = Engine.RegRead<uint>(Arm.Register.PC);
            State = ExecutionState.TerminatedException;

            if (Enum.IsDefined(e.Error))
            {
                _logger.LogTrace(e, "Execution {Id}: Runtime exception.", _executionId);
                // HandleUnicornError() will log to the client

                await this.HandleUnicornError(e.Error).ConfigureAwait(false);
            }
            else
            {
                _logger.LogWarning(e, "Execution {Id}: Exited with unknown Unicorn error code {Code}.", _executionId,
                    e.ErrorId);

                await this.HandleUnknownError(e.ErrorId).ConfigureAwait(false);
            }
        }
        finally
        {
            _runSemaphore.Release();
        }
    }

    private async Task HandleUnicornError(UnicornError error)
    {
        // TODO
    }

    private async Task HandleStopCause()
    {
        switch (_lastStopCause)
        {
            case UnexpectedStopCause.Normal:
                State = ExecutionState.Finished;

                break;
            case UnexpectedStopCause.StrictAccessHook:
                await this.HandleUnicornError(_disallowedStrictAccessType switch
                {
                    MemoryAccessType.Fetch or MemoryAccessType.FetchProtected => UnicornError.FetchUnmapped,
                    MemoryAccessType.Read or MemoryAccessType.ReadProtected => UnicornError.ReadUnmapped,
                    MemoryAccessType.Write or MemoryAccessType.WriteProtected => UnicornError.WriteUnmapped,
                    _ => UnicornError.ReadProtected
                });

                break;
            case UnexpectedStopCause.TrampolineUnbound:
                await this.HandleUnicornError(UnicornError.FetchUnmapped);
                // TODO?

                break;
            case UnexpectedStopCause.TimeoutOrExternalCancellation:
                State = ExecutionState.TerminatedException;

                break;
            default:
                State = ExecutionState.TerminatedException;

                throw new ArgumentOutOfRangeException();
        }
    }

    private async Task HandleUnknownError(int id)
    {
        _logger.LogError("An unknown emulator error occured (Unicorn error code {Code}) .", id);
        await this.SendEvent(new StoppedEvent
        {
            Reason = StoppedEventReason.Exception,
            Description = $"Exited with unknown Unicorn error code {id}."
        });
    }

    private async Task BreakpointHit(AddressBreakpoint breakpoint)
    {
        _logger.LogTrace("Execution {Id}: Breakpoint hit on line {Line} (address {Address:x8}).", _executionId,
            breakpoint.Line, breakpoint.Address);
        State = ExecutionState.Paused;
    }

    private void InitRegisters()
    {
        if (_options.RegisterInitOptions != RegisterInitOptions.Keep
            || _firstRun)
        {
            for (var r = Arm.Register.R0; r <= Arm.Register.R12; r++)
            {
                switch (_options.RegisterInitOptions)
                {
                    case RegisterInitOptions.Clear:
                    case RegisterInitOptions.ClearFirst:
                    case RegisterInitOptions.Keep:
                        Engine.RegWrite(r, 0u);

                        break;
                    case RegisterInitOptions.Randomize:
                    case RegisterInitOptions.RandomizeFirst:
                        Engine.RegWrite(Arm.Register.LR, _rnd.Next(int.MaxValue));

                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            }

            if (_options.RegisterInitOptions is RegisterInitOptions.Randomize or RegisterInitOptions.RandomizeFirst)
                Engine.RegWrite(Arm.Register.LR, (uint)_rnd.Next(int.MaxValue));
            else
                Engine.RegWrite(Arm.Register.LR, 0u);
        }

        Engine.RegWrite(Arm.Register.SP, StackTopAddress);
    }

    public async Task Launch(bool debug, CancellationToken cancellationToken = default, int timeout = Timeout.Infinite)
    {
        this.CheckLoaded();

        // If the token gets cancelled here, it propagates a OperationCanceledException out of the method
        // which is OK
        var entered = (State is ExecutionState.Ready or ExecutionState.Finished or ExecutionState.TerminatedException
                or ExecutionState.TerminatedManually) &&
            await _runSemaphore.WaitAsync(timeout, cancellationToken);
        if (!entered)
        {
            _logger.LogTrace("Execution {Id}: Attempt to launch when not ready.", _executionId);
            _clientLogger.LogError("Cannot launch while the previous launch hasn't finished.");

            throw new InvalidOperationException("Previous execution launch hasn't ended yet.");
        }

        // Launch semaphore acquired
        try
        {
            this.InitMemoryFromExecutable();
            this.InitRegisters();
            this.MakeExits();
        }
        catch
        {
            _runSemaphore.Release();

            throw;
        }

        var startAddress = _exe.EntryPoint;

        _currentCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _currentCts.CancelAfter(_options.Timeout);
        _currentCts.Token.Register(() =>
        {
            _lastStopCause = UnexpectedStopCause.TimeoutOrExternalCancellation;
            Engine.EmuStop(); // Propagates to StartEmulation() which releases the semaphore
        });

        try
        {
            await Task.Run(async () =>
            {
                _currentCts.Token.ThrowIfCancellationRequested();
                await this.StartEmulation(startAddress)
                          .ConfigureAwait(false); // StartEmulation must release the semaphore
            }, _currentCts.Token);
        }
        catch (OperationCanceledException)
        {
            _lastStopCause = UnexpectedStopCause.TimeoutOrExternalCancellation;
            if (State != ExecutionState.Running)
            {
                await this.HandleStopCause().ConfigureAwait(false);
                _runSemaphore.Release();

                return;
            }

            // I don't think it is possible to be in the Running state when this exception is caught
            // But just to make sure
            Engine.EmuStop(); // Would propagate to StartEmulation() which releases the semaphore
        }

        _currentCts.Dispose();
        _currentCts = null;
    }

    public Task Restart(bool debug, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }

    public Task GotoTarget(int targetId)
    {
        throw new NotImplementedException();
    }

    public Task Continue(CancellationToken cancellationToken = default) => throw new NotImplementedException();

    public Task ReverseContinue(CancellationToken cancellationToken = default) => throw new NotImplementedException();

    public async Task Step()
    {
        // TODO
        var entered = await _runSemaphore.WaitAsync(_options.Timeout);
        if (!entered)
        {
            _logger.LogTrace("Execution {Id}: Attempt to step while running.", _executionId);
            _clientLogger.LogError("Cannot step, execution is running.");

            throw new InvalidOperationException("Cannot step, execution is running.");
        }
        
        await this.StartEmulation(_pc, 1);
    }

    public Task StepBack()
    {
        throw new NotImplementedException();
    }

    public Task StepOut(CancellationToken cancellationToken = default) => throw new NotImplementedException();

    public Task Pause()
    {
        throw new NotImplementedException();
    }

    public Task Terminate()
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
        // TODO
        if (_runSemaphore != null!)
            _runSemaphore.Dispose();

        _runSemaphore = null!;
        Engine.Dispose();
    }

    public IEnumerable<DataBreakpointInfoResponse> GetDataBreakpointInfo(string name) =>
        throw new NotImplementedException();

    public EvaluateResponse EvaluateExpression(string expression, EvaluateArgumentsContext? context,
        ValueFormat? format) => throw new NotImplementedException();

    public EvaluateResponse EvaluateExpression(EvaluateArguments arguments) => throw new NotImplementedException();

    public ExceptionInfoResponse GetLastExceptionInfo() => throw new NotImplementedException();

    public IEnumerable<GotoTarget> GetGotoTargets(IAsmFile source, long line, long? column) =>
        throw new NotImplementedException();

    private async Task SendEvent<T>(T @event) where T : IRequest
    {
        await _mediator.Publish(new EngineEvent<T>(this, @event)).ConfigureAwait(false);
    }
}
