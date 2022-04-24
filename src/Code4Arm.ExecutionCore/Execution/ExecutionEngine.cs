// ExecutionEngine.cs
// Author: Ondřej Ondryáš

using System.Buffers;
using System.Collections.Immutable;
using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.Unicorn;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Constants;
using Microsoft.Extensions.Logging;
using Architecture = Code4Arm.Unicorn.Abstractions.Enums.Architecture;

namespace Code4Arm.ExecutionCore.Execution;

public class ExecutionEngine : IExecutionEngine, IRuntimeInfo
{
    private const int MaxArrayPoolSize = 2 * 1024 * 1024;
    private const int MaxStackAllocatedSize = 512;

    internal readonly MemoryStream InputMemoryStream;
    internal readonly MemoryStream OutputMemoryStream;
    private readonly Guid _executionId;
    private readonly ILogger<ExecutionEngine> _logger;
    private readonly ILogger<ExecutionEngine> _clientLogger;
    private Executable? _exe;
    private List<MemorySegment>? _segments;
    private MemorySegment? _stackSegment;
    private ExecutionOptions _options;
    private Random _rnd = new();
    private readonly ArrayPool<byte> _arrayPool;
    private List<UnicornHookRegistration> _strictAccessHooks = new();
    private CancellationTokenSource? _currentCts;
    private uint _pc;
    private UnicornHookRegistration _trampolineHookRegistration;
    private bool _firstRun = true;


    public StepBackMode StepBackMode { get; set; }
    public bool EnableStepBackMemoryCapture { get; set; }
    public bool EnableRegisterDataBreakpoints { get; set; }

    public ExecutionState State { get; private set; }
    public IExecutableInfo? ExecutableInfo => _exe;
    public IRuntimeInfo? RuntimeInfo => _exe == null ? null : this;
    public IDebugProvider? DebugProvider { get; private set; }

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

    public ExecutionEngine(ExecutionOptions options, ILogger<ExecutionEngine> systemLogger,
        ILogger<ExecutionEngine> clientLogger)
    {
        _options = options;

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

    public void LoadExecutable(Executable executable)
    {
        _segments ??= new List<MemorySegment>(executable.Segments.Count + 1);

        // This replaces the segment descriptor in _segments and MAPS MEMORY accordingly
        this.MakeStackSegment();

        if (_exe != null)
        {
            this.UnmapAllMemory();
            _firstRun = false;
        }

        _exe = executable;
        this.MapMemoryFromExecutable();
        this.InitTrampolineHook();

        DebugProvider = new DebugProvider(this);
    }

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
        if (_exe == null || _segments == null)
            throw new InvalidOperationException("Cannot map memory before an executable is loaded.");

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

            this.HandleUnicornError(UnicornError.FetchUnmapped);

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
        if (_exe == null)
            throw new InvalidOperationException("Cannot initialize memory before an executable is loaded.");

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

        this.HandleUnicornError(memoryAccessType switch
        {
            MemoryAccessType.Fetch or MemoryAccessType.FetchProtected => UnicornError.FetchUnmapped,
            MemoryAccessType.Read or MemoryAccessType.ReadProtected => UnicornError.ReadUnmapped,
            MemoryAccessType.Write or MemoryAccessType.WriteProtected => UnicornError.WriteUnmapped,
            _ => UnicornError.ReadProtected
        });
        // TODO
    }

    public IEnumerable<Breakpoint> SetBreakpoints(IAsmFile file, IEnumerable<SourceBreakpoint> breakpoints)
    {
        throw new NotImplementedException();
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

        Span<ulong> exits = stackalloc ulong[2];

        // Breakpoints
        // TODO

        exits[^2] = _exe.LastInstructionAddress + 4;
        exits[^1] = _exe.TextSectionEndAddress; // Is this desirable?

        Engine.SetExits(exits);
    }

    private void StartEmulation(uint startAddress, ulong count = 0ul)
    {
        try
        {
            _logger.LogTrace("Execution {Id}: Starting on {StartAddress:x8}.", _executionId, startAddress);

            _pc = startAddress;
            Engine.EmuStart(startAddress, 0, 0, count);
            _pc = Engine.RegRead<uint>(Arm.Register.PC);

            _logger.LogTrace("Execution {Id}: Ended with PC = {PC:x8}.", _executionId, _pc);
        }
        catch (UnicornException e)
        {
            _pc = Engine.RegRead<uint>(Arm.Register.PC);
            if (Enum.IsDefined(e.Error))
            {
                _logger.LogTrace(e, "Execution {Id}: Runtime exception.", _executionId);
                // HandleUnicornError() will log to the client

                this.HandleUnicornError(e.Error);
            }
            else
            {
                _logger.LogWarning(e, "Execution {Id}: Exited with unknown Unicorn error code {Code}.", _executionId,
                    e.ErrorId);
                _logger.LogError("An unknown emulator error occured (Unicorn error code {Code}) .", e.ErrorId);

                throw;
            }
        }
    }

    private void HandleUnicornError(UnicornError error)
    {
        // TODO
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

    public async Task Launch(bool debug, CancellationToken cancellationToken = default)
    {
        if (_exe == null)
            throw new InvalidOperationException("Executable not loaded.");

        this.InitMemoryFromExecutable();
        this.InitRegisters();
        this.MakeExits();

        var startAddress = _exe.EntryPoint;

        _currentCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _currentCts.CancelAfter(_options.Timeout);
        _currentCts.Token.Register(() => { Engine.EmuStop(); });

        try
        {
            await Task.Run(() =>
            {
                _currentCts.Token.ThrowIfCancellationRequested();
                this.StartEmulation(startAddress);
            }, _currentCts.Token);
        }
        catch (OperationCanceledException)
        {
            Engine.EmuStop();
            _pc = Engine.RegRead<uint>(Arm.Register.PC);
        }

        _currentCts.Dispose();
        _currentCts = null;
    }

    public void Restart(bool debug, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }

    public void GotoTarget(int targetId)
    {
        throw new NotImplementedException();
    }

    public Task Continue(CancellationToken cancellationToken = default) => throw new NotImplementedException();

    public Task ReverseContinue(CancellationToken cancellationToken = default) => throw new NotImplementedException();

    public void Step()
    {
        throw new NotImplementedException();
    }

    public void StepBack()
    {
        throw new NotImplementedException();
    }

    public Task StepOut(CancellationToken cancellationToken = default) => throw new NotImplementedException();

    public void Pause()
    {
        throw new NotImplementedException();
    }

    public void Terminate()
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
        // TODO
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
}
