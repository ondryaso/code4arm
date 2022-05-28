// ExecutionEngine.cs
// Author: Ondřej Ondryáš

using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using System.Runtime.CompilerServices;
using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Dwarf;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionCore.Protocol.Events;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.Unicorn;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Abstractions.Extensions;
using Code4Arm.Unicorn.Callbacks.Native;
using Code4Arm.Unicorn.Constants;
using MediatR;
using Microsoft.Extensions.Logging;
using Architecture = Code4Arm.Unicorn.Abstractions.Enums.Architecture;

namespace Code4Arm.ExecutionCore.Execution;

public class ExecutionEngine : IExecutionEngine, IRuntimeInfo
{
    /// <summary>
    /// A <see cref="Breakpoint"/> with information about the target instruction's address in memory. 
    /// </summary>
    internal record AddressBreakpoint : Breakpoint
    {
        public uint Address { get; init; }
    }

    /// <summary>
    /// Determines possible causes for an end of an emulation cycle.
    /// </summary>
    /// <seealso cref="ExecutionEngine.StartEmulation"/>
    internal enum StopCause
    {
        Normal,
        Interrupt,
        InvalidInstruction,
        InvalidMemoryAccess,
        TrampolineUnbound,
        TimeoutOrExternalCancellation,
        UnicornException,
        InternalException,
        ExternalPause,
        DataBreakpoint
    }

    /// <summary>
    /// A container for different kinds of data used when handling the end of an emulation cycle. 
    /// </summary>
    internal struct StopData
    {
        /// <summary>
        /// The number of interrupt that caused an <see cref="StopCause.Interrupt"/> stop.
        /// </summary>
        public uint InterruptNumber;

        /// <summary>
        /// The value of the R7 register after an interrupt stops the execution.
        /// Used when handling an <see cref="StopCause.Interrupt"/> stop.
        /// </summary>
        public uint InterruptR7;

        /// <summary>
        /// The type of invalid memory access that caused an <see cref="StopCause.InvalidMemoryAccess"/> stop.
        /// </summary>
        public MemoryAccessType AccessType;

        /// <summary>
        /// An address of a memory location that an instruction attempted to access.
        /// Used when handling an <see cref="StopCause.InvalidMemoryAccess"/> or
        /// a <see cref="StopCause.TrampolineUnbound"/> stop.
        /// </summary>
        public uint InvalidAddress;

        /// <summary>
        /// The Unicorn error ID returned from Unicorn. Used when handling
        /// a <see cref="StopCause.UnicornException"/> stop.
        /// </summary>
        public UnicornError UnicornError;

        /// <summary>
        /// The string error message returned from Unicorn. Used when handling
        /// a <see cref="StopCause.UnicornException"/> stop.
        /// </summary>
        public string UnicornErrorMessage;

        /// <summary>
        /// The DataBreakpoint ID (managed by DebugProvider) of the breakpoint that caused
        /// a <see cref="StopCause.DataBreakpoint"/> stop cause.
        /// </summary>
        public long DataBreakpointId;

        /// <summary>
        /// Signalises that when handling a <see cref="StopCause.DataBreakpoint"/> stop, the PC should be incremented.
        /// Used in memory-watching traces which stop the emulation from a memory hook -> before PC is incremented.
        /// </summary>
        public bool MovePcAfterDataBreakpoint;
    }

    /// <summary>
    /// A dummy Thread ID used in all requests and responses that require one (mainly Stopped events).
    /// Threads are not supported by this engine/debugger.
    /// </summary>
    public const long ThreadId = 1;

    /// <summary>
    /// The maximum size of array that may be rented from <see cref="ArrayPool"/>.
    /// If a larger array is required, it will be allocated normally.
    /// </summary>
    /// <seealso cref="MakeStackSegment"/>
    internal const int MaxArrayPoolSize = 2 * 1024 * 1024;

    /// <summary>
    /// The maximum size of array that may be allocated on stack using <see langword="stackalloc"/>.
    /// </summary>
    /// <seealso cref="RandomizeMemory"/>
    /// <see cref="ClearMemory"/>
    internal const int MaxStackAllocatedSize = 512;

    /// <summary>
    /// A unique ID of this engine instance. Used for logging purposes only.
    /// </summary>
    private readonly Guid _executionId;

    internal DwarfLineAddressResolver? LineResolver;
    internal AddressBreakpoint? CurrentBreakpoint;

    /// <summary>
    /// If false, Breakpoints will be disabled and DataBreakpoints will continue execution without stopping.
    /// </summary>
    /// <seealso cref="InitLaunch"/>
    internal bool DebuggingEnabled = true;

    /// <summary>
    /// The current value of the program counter. Updated from Unicorn after an end of an emulation cycle.
    /// </summary>
    internal uint CurrentPc;

    /// <summary>
    /// The line (zero-indexed) in a source pointed to by <see cref="CurrentStopSourceIndex"/> that contains the
    /// instruction at the memory address determined by <see cref="CurrentPc"/>. Updated after an end of an emulation
    /// cycle. May be -1 if the line cannot be determined.
    /// </summary>
    internal int CurrentStopLine;

    /// <summary>
    /// An index to the <see cref="IExecutableInfo.Sources"/> array of the current <see cref="ExecutableInfo"/> that
    /// determines the source file that contains the instruction at the memory address determined by
    /// <see cref="CurrentPc"/>. Updated after an end of an emulation cycle. May be -1 if the instruction source
    /// cannot be determined.
    /// </summary>
    internal int CurrentStopSourceIndex;

    internal StopCause LastStopCause = StopCause.Normal;
    internal StopData LastStopData;

    internal readonly ArrayPool<byte> ArrayPool;

    private readonly ILogger<ExecutionEngine> _logger;
    private readonly IMediator _mediator;
    private readonly DebugProvider _debugProvider;
    private readonly Dictionary<nuint, Delegate> _nativeCodeHooks = new();
    private readonly Dictionary<uint, AddressBreakpoint> _currentBreakpoints = new();
    private readonly List<UnicornHookRegistration> _strictAccessHooks = new();
    private readonly Stack<IUnicornContext>? _stepBackContexts;

    private Executable? _exe;
    private List<MemorySegment>? _segments;
    private MemorySegment? _stackSegment;
    private ExecutionOptions _options;
    private Random _rnd = new();
    private CancellationTokenSource? _currentCts;
    private UnicornHookRegistration _trampolineHookRegistration;
    private bool _firstRun = true;
    private bool _breakpointExitsDisabled = false;

    private readonly ManualResetEventSlim _configurationDoneEvent = new(false);
    private readonly SemaphoreSlim _runSemaphore = new(1);

    public ExecutionState State { get; private set; }
    public IExecutableInfo? ExecutableInfo => _exe;
    public IRuntimeInfo? RuntimeInfo => _exe == null ? null : this;
    public IDebugProvider DebugProvider => _debugProvider;
    public IDebugProtocolSourceLocator SourceLocator => _debugProvider;
    public uint StackStartAddress { get; private set; }
    public uint StackSize => _options.StackSize;
    public uint StackTopAddress { get; private set; }
    public uint StackEndAddress { get; private set; }

    internal ExecutionOptions Options => _options;

    public IReadOnlyList<MemorySegment> Segments =>
        _segments as IReadOnlyList<MemorySegment> ?? ImmutableList<MemorySegment>.Empty;

    public uint ProgramCounter => CurrentPc;

    public IUnicorn Engine { get; }

    private readonly StringWriter _emulatedOut;
    public TextWriter EmulatedOutput => _emulatedOut;

    public ExecutionEngine(ExecutionOptions options, DebuggerOptions debuggerOptions, IMediator mediator,
        ILogger<ExecutionEngine> systemLogger)
    {
        _options = options;
        _mediator = mediator;

        Engine = this.MakeUnicorn();
        State = ExecutionState.Unloaded;

        ArrayPool = ArrayPool<byte>.Shared;

        _logger = systemLogger;
        _executionId = Guid.NewGuid();
        _emulatedOut = new StringWriter();

        _debugProvider = new DebugProvider(this, debuggerOptions);

        if (options.StepBackMode != StepBackMode.None)
        {
            _stepBackContexts = new Stack<IUnicornContext>();
        }

        _logger.LogInformation("Execution {Id}: Created.", _executionId);
    }

    /// <summary>
    /// Initializes and configures Unicorn. Creates hooks for interrupts, invalid instructions and invalid memory
    /// accesses. 
    /// </summary>
    /// <returns>The created and initialized <see cref="IUnicorn"/> instance.</returns>
    private IUnicorn MakeUnicorn()
    {
        var unicorn = new Unicorn.Unicorn(Architecture.Arm, EngineMode.Arm | EngineMode.LittleEndian);
        unicorn.CheckIfBindingMatchesLibrary(true);

        unicorn.CpuModel = Arm.Cpu.MAX;
        unicorn.EnableMultipleExits();

        unicorn.AddInterruptHook(this.InterruptHookHandler);
        unicorn.AddInvalidInstructionHook(this.InvalidInstructionHandler);
        unicorn.AddInvalidMemoryAccessHook(this.InvalidMemoryAccessHandler, MemoryHookType.AllInvalidEvents, 0,
            uint.MaxValue);

        return unicorn;
    }

    #region Initialization

    /// <summary>
    /// Creates a <see cref="MemorySegment"/> for the stack and maps it to Unicorn virtual memory.
    /// Its placement (address range) and initial contents are controlled by <see cref="ExecutionOptions.StackPlacementOptions"/>.
    /// </summary>
    /// <remarks>
    /// 
    /// </remarks>
    /// <exception cref="InvalidOperationException"></exception>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
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
                keptStackData = rented ? ArrayPool.Rent((int)keptSize) : new byte[keptSize];
                Engine.MemRead(_stackSegment.StartAddress, keptStackData, keptSize);
            }

            Engine.MemUnmap(_stackSegment.StartAddress, _stackSegment.Size);
            Engine.MemMap(newStackSegment.StartAddress, newStackSegment.Size,
                MemoryPermissions.Read | MemoryPermissions.Write);

            if (keptStackData != null)
            {
                Engine.MemWrite(stackSegmentBegin, keptStackData, keptSize);

                if (rented)
                    ArrayPool.Return(keptStackData);
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
    public async Task LoadExecutable(Executable executable)
    {
        if (executable == null)
            throw new ArgumentNullException(nameof(executable));

        await this.LogDebugConsole("Loading executable.");

        // TODO: remove this
        await this.LogDebugConsole(typeof(Executable)
                                   .GetField("_filePath", BindingFlags.Instance | BindingFlags.NonPublic)
                                   !.GetValue(executable) as string ?? "");

        _segments ??= new List<MemorySegment>(executable.Segments.Count + 1);

        // This replaces the segment descriptor in _segments and MAPS MEMORY accordingly
        this.MakeStackSegment();

        if (_exe != null)
        {
            this.UnmapAllMemory();
            _firstRun = false;
        }

        _exe = executable;

        LineResolver = new DwarfLineAddressResolver(_exe.Elf);

        this.MapMemoryFromExecutable();
        this.InitTrampolineHook();

        State = ExecutionState.Ready;
    }
#pragma warning restore CS8774

    private void MapMemoryFromExecutable()
    {
        this.CheckLoaded();

        foreach (var segment in _exe.Segments)
        {
            // TODO: this could also be used for certain StepBack variants
            if (Options.EnableAccurateExecutionTracking &&
                segment.Permissions.HasFlag(MemorySegmentPermissions.Execute))
            {
                var callback = new CodeHookNativeCallback(this.CodeHookNativeHandler);
                var handle = Engine.AddNativeHook(callback, UniConst.Hook.Code, segment.StartAddress,
                    segment.EndAddress);
                _nativeCodeHooks.Add(handle, callback);
            }

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
                    _strictAccessHooks.Add(Engine.AddMemoryHook(this.StrictAccessHandler,
                        MemoryHookType.Read | MemoryHookType.Write | MemoryHookType.Fetch,
                        segment.StartAddress, segment.ContentsStartAddress - 1));
                }

                if (segment.EndAddress != segment.ContentsEndAddress)
                {
                    _strictAccessHooks.Add(Engine.AddMemoryHook(this.StrictAccessHandler,
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

        _trampolineHookRegistration = Engine.AddCodeHook(this.TrampolineHandler, trampoline.StartAddress,
            trampoline.EndAddress);
    }

    /// <summary>
    /// Load data of segments from the executable.
    /// </summary>
    /// <remarks>
    /// This is used just before emulation is started. It overwrites the current contents of virtual memory with data
    /// from the executable and zeroes out BSS sections.
    /// </remarks>
    private void InitMemoryFromExecutable()
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
                    case RegisterInitOptions.Keep:
                        Engine.RegWrite(r, 0u);

                        break;
                    case RegisterInitOptions.Randomize:
                    case RegisterInitOptions.RandomizeFirst:
                        Engine.RegWrite(r, _rnd.Next(int.MaxValue));

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

        if (_options.SimdRegisterInitOptions != RegisterInitOptions.Keep || _firstRun)
        {
            for (var r = Arm.Register.D0; r <= Arm.Register.D31; r++)
            {
                switch (_options.SimdRegisterInitOptions)
                {
                    case RegisterInitOptions.Clear:
                    case RegisterInitOptions.Keep:
                        Engine.RegWrite(r, 0ul);

                        break;
                    case RegisterInitOptions.Randomize:
                    case RegisterInitOptions.RandomizeFirst:
                        Engine.RegWrite(r, -1024.0 + (_rnd.NextDouble() * 2048.0));

                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }
            }
        }

        // TODO: Initialize the CPU somehow and switch to User mode ???
        // This just switches it to User mode (16 because of RES1 at bit 4)
        Engine.RegWrite(Arm.Register.CPSR, 16);
        Engine.RegWrite(Arm.Register.SP, StackTopAddress);

        // VFP
        Engine.RegWrite(Arm.Register.FPEXC, 0x40000000);
    }

    private void UnmapAllMemory()
    {
        if (_segments == null)
            return;

        foreach (var strictAccessHook in _strictAccessHooks)
        {
            strictAccessHook.RemoveHook();
        }

        foreach (var nativeCodeHookRef in _nativeCodeHooks.Keys)
        {
            Engine.RemoveNativeHook(nativeCodeHookRef);
        }

        _nativeCodeHooks.Clear();

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

    #endregion

    #region Unicorn hook handlers

    private void CodeHookNativeHandler(UIntPtr engine, ulong address, uint size, IntPtr userData)
    {
        _debugProvider.RefreshSteppedTraces();
    }

    private void StrictAccessHandler(IUnicorn engine, MemoryAccessType memoryAccessType, ulong address, int size,
        long value)
    {
        _logger.LogTrace(
            "Execution {Id}: Access ({AccessType}) to a side chunk of memory around a segment at {Address:x8}.",
            _executionId, memoryAccessType, address);

        LastStopCause = StopCause.InvalidMemoryAccess;
        LastStopData.AccessType = memoryAccessType;
        LastStopData.InvalidAddress = (uint)address;

        Engine.EmuStop();
    }

    private void TrampolineHandler(IUnicorn engine, ulong address, uint size)
    {
        if (_exe is not { FunctionSimulators: { } } ||
            !_exe.FunctionSimulators.TryGetValue((uint)address, out var simulator))
        {
            _logger.LogTrace("Execution {Id}: Trampoline hook on unbound address {Address:x8}.", _executionId, address);

            LastStopCause = StopCause.TrampolineUnbound;
            LastStopData.InvalidAddress = (uint)address;

            Engine.EmuStop();

            return;
        }

        CurrentPc = (uint)address;
        try
        {
            simulator.FunctionSimulator.Run(this);
        }
        catch (UnicornException e)
        {
            if (e.Error.IsMemoryError())
            {
                LastStopCause = StopCause.InvalidMemoryAccess;
                // The actual memory access handler may or may not be called here
            }
        }
        catch (Exception e)
        {
            LastStopCause = StopCause.InternalException;
            _logger.LogError(e, "Execution {Id}: Function simulator exception.", _executionId);
        }
    }

    private void InterruptHookHandler(IUnicorn engine, uint interruptNumber)
    {
        _logger.LogTrace("Execution {Id}: Interrupt {Interrupt:x}.", _executionId, interruptNumber);

        LastStopCause = StopCause.Interrupt;
        LastStopData.InterruptNumber = interruptNumber;

        Engine.EmuStop();
        LastStopData.InterruptR7 = engine.RegRead<uint>(Arm.Register.R7);
    }

    private bool InvalidInstructionHandler(IUnicorn engine)
    {
        _logger.LogTrace("Execution {Id}: Invalid instruction.", _executionId);

        LastStopCause = StopCause.InvalidInstruction;

        Engine.EmuStop();

        return false;
    }

    private bool InvalidMemoryAccessHandler(IUnicorn engine, MemoryAccessType memoryAccessType, ulong address, int size,
        long value)
    {
        _logger.LogTrace("Execution {Id}: Invalid memory access ({AccessType}) at {Address:x8}.", _executionId,
            memoryAccessType, address);

        LastStopCause = StopCause.InvalidMemoryAccess;
        LastStopData.AccessType = memoryAccessType;
        LastStopData.InvalidAddress = (uint)address;

        Engine.EmuStop();

        return false;
    }

    #endregion

    #region Setting breakpoints

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
        var address = LineResolver!.GetAddress(sourceCompilationPath, tryingLine + 1);
        var successful = true;

        while (address == uint.MaxValue && tryingLine < sourceObject.ProgramLines)
        {
            successful = false;
            tryingLine++;

            for (; tryingLine < sourceObject.ProgramLines; tryingLine++)
            {
                if (!sourceObject.IsProgramLine![tryingLine])
                    continue;

                address = LineResolver!.GetAddress(sourceCompilationPath, tryingLine + 1);
                successful = true;

                break;
            }
        }

        return successful ? (tryingLine, address) : (-1, 0);
    }

    public IEnumerable<Breakpoint> SetBreakpoints(Source file, IEnumerable<SourceBreakpoint> breakpoints)
    {
        this.CheckLoaded();

        var sourceCompilationPath = _debugProvider.GetCompilationPathForSource(file);
        var sourceObject = _debugProvider.GetObjectForSource(file);

        if (sourceCompilationPath == null || sourceObject == null)
            throw new InvalidSourceException($"Cannot set breakpoints in file {file.Name ?? file.Path}.");

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
        this.CheckLoaded();

        _debugProvider.ClearDataBreakpoints();
        foreach (var dataBreakpoint in dataBreakpoints)
        {
            yield return _debugProvider.SetDataBreakpoint(dataBreakpoint);
        }
    }

    public IEnumerable<Breakpoint> SetExceptionBreakpoints(IEnumerable<string> filterIds)
    {
        // TODO
        return filterIds.Select(f => new Breakpoint()
        {
            Verified = true
        });
    }

    public IEnumerable<Breakpoint> SetFunctionBreakpoints(IEnumerable<FunctionBreakpoint> functionBreakpoints)
    {
        throw new NotImplementedException();
    }

    public IEnumerable<Breakpoint> SetInstructionBreakpoints(IEnumerable<InstructionBreakpoint> instructionBreakpoints)
    {
        throw new NotImplementedException();
    }

    #endregion

    #region Emulation finished logic

    private int DetermineSourceIndexForAddress(uint address)
    {
        for (var i = 0; i < _exe!.SourceObjects.Count; i++)
        {
            var startAddress = _exe.TextSectionStarts[i];
            var endAddress = (i == (_exe.SourceObjects.Count - 1))
                ? _exe.TextSectionEndAddress
                : _exe.TextSectionStarts[i + 1];

            var a = (long)address;

            if (a >= startAddress && a < endAddress)
                return i;
        }

        return -1;
    }

    private void DetermineCurrentStopPositions()
    {
        CurrentPc = Engine.RegRead<uint>(Arm.Register.PC);
        var pc = CurrentPc;

        if (LastStopCause == StopCause.Interrupt)
            pc -= 4; // The PC is moved after an interrupt

        var lineInfo = LineResolver!.GetSourceLine(pc, out var displacement);
        if (displacement != 0)
        {
            CurrentStopLine = -1;
            CurrentStopSourceIndex = this.DetermineSourceIndexForAddress(pc);
        }
        else
        {
            CurrentStopLine = (int)lineInfo.Line - 1; // in DWARF, the lines are numbered from 1
            var i = 0;
            foreach (var exeSource in _exe!.Sources)
            {
                if (exeSource.BuildPath.Equals(lineInfo.File.Path, StringComparison.OrdinalIgnoreCase))
                    break;

                i++;
            }

            CurrentStopSourceIndex = (i == _exe!.Sources.Count ? -1 : i);
        }
    }

    private async Task BreakpointHit(AddressBreakpoint breakpoint)
    {
        await this.LogDebugConsole("Hit breakpoint.", true);

        State = ExecutionState.PausedBreakpoint;
        CurrentBreakpoint = breakpoint;

        await this.SendEvent(new StoppedEvent()
        {
            Reason = StoppedEventReason.Breakpoint,
            Description = "Breakpoint hit",
            HitBreakpointIds = new Container<long>(breakpoint.Id ?? 0),
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    private async Task StepDone()
    {
        State = ExecutionState.Paused;

        await this.SendEvent(new StoppedEvent()
        {
            Reason = StoppedEventReason.Step,
            Description = "Stepped",
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    private async Task HandleStopCause()
    {
        switch (LastStopCause)
        {
            case StopCause.InvalidMemoryAccess:
                await this.HandleInvalidMemoryAccess();

                break;
            case StopCause.TrampolineUnbound:
                await this.HandleTrampolineUnbound();

                break;
            case StopCause.TimeoutOrExternalCancellation:
                await this.HandleTimeout();

                break;
            case StopCause.Interrupt:
                if (LastStopData.InterruptR7 == 0xFF000000u)
                    await this.EmulationEnded();
                else
                    await this.HandleInterrupt();

                break;
            case StopCause.InvalidInstruction:
                await this.HandleInvalidInstruction();

                break;
            case StopCause.UnicornException:
                await this.HandleUnicornError();

                break;
            case StopCause.InternalException:
                await this.HandleException();

                break;
            case StopCause.ExternalPause:
                await this.HandlePause();

                break;
            case StopCause.DataBreakpoint:
                if (!DebuggingEnabled)
                    await this.StartEmulation(CurrentPc);
                else
                    await this.HandleDataBreakpoint();

                break;
            default:
                throw new InvalidOperationException("Invalid stop cause.");
            case StopCause.Normal:
                _logger.LogWarning("Execution {Id}: StopCause Normal in HandleStopCause.", _executionId);
                await this.EmulationEnded();

                break;
        }
    }

    private async Task HandleDataBreakpoint()
    {
        if (LastStopData.MovePcAfterDataBreakpoint)
        {
            // Used in data hooks which stop the emulation from a memory hook -> before PC is incremented
            Engine.RegWrite(Arm.Register.PC, CurrentPc + 4);
            this.DetermineCurrentStopPositions();
        }

        await _debugProvider.LogTraceInfo();

        State = ExecutionState.PausedBreakpoint;
        CurrentBreakpoint = null;

        await this.SendEvent(new StoppedEvent()
        {
            Reason = StoppedEventReason.DataBreakpoint,
            Description = "Data breakpoint hit",
            HitBreakpointIds = new Container<long>(LastStopData.DataBreakpointId),
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    private async Task EmulationEnded()
    {
        _logger.LogTrace("Execution {Id}: Ended.", _executionId);
        await this.LogDebugConsole("Execution finished normally.");

        State = ExecutionState.Finished;

        await this.SendEvent(new TerminatedEvent());
        await Task.Delay(500);
        await this.SendEvent(new ExitedEvent() { ExitCode = 0 }); // TODO read exit code
    }

    private async Task HandlePause()
    {
        var onBreakpoint = _currentBreakpoints.TryGetValue(CurrentPc, out var breakpoint);

        State = ExecutionState.Paused;

        await this.SendEvent(new StoppedEvent()
        {
            Reason = StoppedEventReason.Pause,
            Description = "Paused",
            HitBreakpointIds = onBreakpoint ? new Container<long>(breakpoint!.Id ?? 0) : null,
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    private async Task HandleUnicornError()
    {
        _logger.LogTrace("Execution {Id}: Unicorn error {ErrorId}.", _executionId, LastStopData.UnicornError);
        await this.LogDebugConsole($"Emulator error: {LastStopData.UnicornErrorMessage}.");

        State = ExecutionState.PausedException;

        await this.SendEvent(new StoppedEvent
        {
            Reason = StoppedEventReason.Exception,
            Description = $"Unicorn error: {LastStopData.UnicornError}",
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    private async Task HandleException()
    {
        await this.LogDebugConsole("Emulator internal error.");

        State = ExecutionState.PausedException;

        await this.SendEvent(new StoppedEvent
        {
            Reason = StoppedEventReason.Exception,
            Description = "Unexpected execution error",
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    private async Task HandleInvalidMemoryAccess()
    {
        await this.LogDebugConsole("Invalid memory access.", true, OutputEventGroup.Start);
        await this.LogDebugConsole($"Memory address: {LastStopData.InvalidAddress:x8}");
        await this.LogDebugConsole($"Access type: {LastStopData.AccessType}");
        if (Options.EnableAccurateExecutionTracking)
            await this.LogDebugConsole($"Current PC: {CurrentPc:x8}");
        else
            await this.LogDebugConsole(
                "Current PC address cannot be determined accurately because of the current configuration.");
        await this.LogDebugConsole(string.Empty, false, OutputEventGroup.End);

        State = ExecutionState.PausedException;

        await this.SendEvent(new StoppedEvent
        {
            Reason = StoppedEventReason.Exception,
            Description = "Invalid memory access",
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    private async Task HandleTrampolineUnbound()
    {
        var trampoline = _segments?.FirstOrDefault(s => s.IsTrampoline);
        if (trampoline == null)
        {
            await this.HandleInvalidMemoryAccess();

            return;
        }

        await this.LogDebugConsole("Invalid memory access.", true, OutputEventGroup.Start);
        await this.LogDebugConsole($"Memory address: {LastStopData.InvalidAddress:x8}");
        await this.LogDebugConsole(
            $"The memory range {trampoline.StartAddress:x} to {trampoline.EndAddress:x} is used as the target " +
            "for jumps to simulated function symbols. Only those addresses that match a simulated function can be " +
            "accessed. Check your configuration.");
        await this.LogDebugConsole(string.Empty, false, OutputEventGroup.End);

        State = ExecutionState.PausedException;

        await this.SendEvent(new StoppedEvent
        {
            Reason = StoppedEventReason.Exception,
            Description = "Invalid memory access",
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    private async Task HandleTimeout()
    {
        _logger.LogTrace("Execution {Id}: Timed out.", _executionId);
        await this.LogDebugConsole("The execution has timed out.");

        State = ExecutionState.Finished;

        await this.SendEvent(new TerminatedEvent());
        await Task.Delay(500);
        await this.SendEvent(new ExitedEvent() { ExitCode = 1 });
    }

    private async Task HandleInterrupt()
    {
        State = ExecutionState.PausedException;

        await this.SendEvent(new StoppedEvent()
        {
            Reason = StoppedEventReason.Exception,
            Description = $"Paused on interrupt {LastStopData.InterruptNumber}",
            Text = $"Interrupt {LastStopData.InterruptNumber}",
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    private async Task HandleInvalidInstruction()
    {
        State = ExecutionState.PausedException;

        await this.SendEvent(new StoppedEvent()
        {
            Reason = StoppedEventReason.Exception,
            Description = "Paused on invalid instruction",
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    #endregion

    #region Main execution flow logic

    private async Task StartEmulation(uint startAddress, ulong count = 0ul)
    {
        try
        {
            _logger.LogTrace("Execution {Id}: Starting on {StartAddress:x8}.", _executionId, startAddress);
            await this.LogDebugConsole($"Running at {startAddress:x8}.", true);

            LastStopCause = StopCause.Normal;
            State = ExecutionState.Running;

            CurrentPc = startAddress;
            Engine.EmuStart(startAddress, 0, 0, count);

            if (_currentCts != null)
            {
                _currentCts.Dispose();
                _currentCts = null;
            }

            this.DetermineCurrentStopPositions();
            await this.HandleEmulatedOutputBuffer();
            _debugProvider.ClearEvaluateVariables();

            try
            {
                if (LastStopCause != StopCause.Normal)
                {
                    await this.HandleStopCause();
                }
                else if (_currentBreakpoints.TryGetValue(CurrentPc, out var breakpoint))
                {
                    await this.BreakpointHit(breakpoint);
                }
                else if (count != 0)
                {
                    await this.StepDone();
                }
                else
                {
                    await this.EmulationEnded();
                }
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Execution {Id}: Emulation result handling exception.", _executionId);
                // TODO: T E R M I N A R L O  T O D O

                throw;
            }
        }
        catch (UnicornException e)
        {
            this.DetermineCurrentStopPositions();

            if (LastStopCause == StopCause.Normal)
            {
                LastStopCause = StopCause.UnicornException;
                LastStopData.UnicornError = e.Error;
                LastStopData.UnicornErrorMessage = e.Message;
            }

            await this.HandleEmulatedOutputBuffer();
            _debugProvider.ClearEvaluateVariables();
            await this.HandleStopCause();

            if (!Enum.IsDefined(e.Error))
                _logger.LogWarning(e, "Execution {Id}: Exited with unknown Unicorn error code {Code}.", _executionId,
                    e.ErrorId);
        }
        finally
        {
            _runSemaphore.Release();
        }
    }

    public async Task InitLaunch(bool debug, int enterTimeout = Timeout.Infinite, bool waitForLaunch = true)
    {
        this.CheckLoaded();

        // If the token gets cancelled here, it propagates a OperationCanceledException out of the method
        // which is OK
        var entered = (State is ExecutionState.Ready or ExecutionState.Finished) &&
            await _runSemaphore.WaitAsync(enterTimeout);

        if (!entered)
        {
            _logger.LogTrace("Execution {Id}: Attempt to launch when not ready.", _executionId);

            throw new Exception(); // TODO
        }

        DebuggingEnabled = debug;
        _breakpointExitsDisabled = !debug;

        // Launch semaphore acquired
        try
        {
            this.InitMemoryFromExecutable();
            this.InitRegisters();
            this.MakeExits();

            LastStopCause = StopCause.Normal;

            _currentCts?.Dispose();
            _currentCts = new CancellationTokenSource();
            _currentCts.CancelAfter(_options.Timeout);
            _currentCts.Token.Register(() =>
            {
                LastStopCause = StopCause.TimeoutOrExternalCancellation;
                Engine.EmuStop(); // If running, propagates to StartEmulation() which releases the semaphore
            });
        }
        catch
        {
            _runSemaphore.Release();

            throw;
        }

        try
        {
            var startAddress = _exe.EntryPoint;

            _ = Task.Run(async () =>
            {
                if (_currentCts.IsCancellationRequested)
                {
                    await this.ExitOnTimeout();

                    return;
                }

                if (waitForLaunch)
                {
                    try
                    {
                        _configurationDoneEvent.Wait(_currentCts.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        await this.ExitOnTimeout();

                        return;
                    }

                    if (_currentCts.IsCancellationRequested)
                    {
                        await this.ExitOnTimeout();

                        return;
                    }
                }

                await this.SendEvent(new ProcessEvent()
                {
                    Name = "code4arm-emulation",
                    IsLocalProcess = false,
                    PointerSize = 32,
                    StartMethod = ProcessEventStartMethod.Launch
                });

                await this.StartEmulation(startAddress); // StartEmulation must release the semaphore
            }, _currentCts.Token);
        }
        catch (OperationCanceledException)
        {
            await this.ExitOnTimeout();
        }
    }

    public Task Launch()
    {
        _configurationDoneEvent.Set();

        return Task.CompletedTask;
    }

    public Task Restart(bool debug)
    {
        throw new NotImplementedException();
    }

    public async Task GotoTarget(long targetId, int enterTimeout = Timeout.Infinite)
    {
        this.CheckLoaded();

        var address = (uint)targetId;

        if (address < _exe.TextSectionStartAddress || address >= _exe.TextSectionEndAddress || (address % 4) != 0)
            throw new InvalidGotoTargetException();

        var entered =
            (State is ExecutionState.Paused or ExecutionState.PausedBreakpoint or ExecutionState.PausedException)
            && await _runSemaphore.WaitAsync(enterTimeout);

        if (!entered)
        {
            _logger.LogTrace("Execution {Id}: Attempt to goto while running.", _executionId);

            throw new InvalidOperationException("Cannot jump to target, execution is running.");
        }

        Engine.RegWrite(Arm.Register.PC, address);

        this.DetermineCurrentStopPositions();
        _runSemaphore.Release();

        State = ExecutionState.Paused;

        await this.SendEvent(new StoppedEvent()
        {
            Description = "Changed PC",
            Reason = StoppedEventReason.Goto,
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    public async Task Continue(int enterTimeout = Timeout.Infinite)
    {
        this.CheckLoaded();

        // If the token gets cancelled here, it propagates a OperationCanceledException out of the method
        // which is OK
        var entered = (State is ExecutionState.Paused or ExecutionState.PausedBreakpoint
                or ExecutionState.PausedException) &&
            await _runSemaphore.WaitAsync(enterTimeout);

        if (!entered)
        {
            _logger.LogTrace("Execution {Id}: Attempt to continue when not paused.", _executionId);

            throw new Exception(); // TODO
        }

        // Launch semaphore acquired
        try
        {
            if (State == ExecutionState.PausedBreakpoint)
            {
                _breakpointExitsDisabled = true;
                this.MakeExits();

                // TODO: is this safe?
                Engine.EmuStart(CurrentPc, 0, 0, 1);
                CurrentPc = Engine.RegRead<uint>(Arm.Register.PC);

                if (DebuggingEnabled)
                {
                    _breakpointExitsDisabled = false;
                    this.MakeExits();
                }
            }
            else if (DebuggingEnabled && _breakpointExitsDisabled)
            {
                _breakpointExitsDisabled = false;
                this.MakeExits();
            }

            if (Options.StepBackMode == StepBackMode.CaptureOnStep)
            {
                foreach (var stepBackContext in _stepBackContexts!)
                {
                    stepBackContext.Dispose();
                }

                _stepBackContexts.Clear();
            }

            LastStopCause = StopCause.Normal;

            _currentCts?.Dispose();
            _currentCts = new CancellationTokenSource();
            _currentCts.CancelAfter(_options.Timeout);
            _currentCts.Token.Register(() =>
            {
                LastStopCause = StopCause.TimeoutOrExternalCancellation;
                Engine.EmuStop(); // If running, propagates to StartEmulation() which releases the semaphore
            });
        }
        catch
        {
            _runSemaphore.Release();

            throw;
        }

        var startAddress = CurrentPc;
        try
        {
            _ = Task.Run(async () =>
            {
                if (_currentCts.IsCancellationRequested)
                {
                    await this.ExitOnTimeout();

                    return;
                }

                await this.SendEvent(new ContinuedEvent()
                {
                    ThreadId = ThreadId,
                    AllThreadsContinued = true
                });

                await this.StartEmulation(startAddress); // StartEmulation must release the semaphore
            }, _currentCts.Token);
        }
        catch (OperationCanceledException)
        {
            await this.ExitOnTimeout();
        }
    }

    public Task ReverseContinue() => throw new NotImplementedException();

    public async Task Step(int enterTimeout = Timeout.Infinite)
    {
        var entered = await _runSemaphore.WaitAsync(enterTimeout);
        if (!entered)
        {
            _logger.LogTrace("Execution {Id}: Attempt to step while running.", _executionId);

            throw new InvalidOperationException("Cannot step, execution is running.");
        }

        if (_options.StepBackMode == StepBackMode.CaptureOnStep)
        {
            var context = Engine.SaveContext();
            _stepBackContexts!.Push(context);
        }

        if (!_breakpointExitsDisabled)
        {
            _breakpointExitsDisabled = true;
            this.MakeExits();
        }

        Engine.RemoveTbCache(CurrentPc, CurrentPc + 4096); // See Unicorn issue #1606
        await this.StartEmulation(CurrentPc, 1);
    }

    public async Task StepBack(int enterTimeout = Timeout.Infinite)
    {
        if (_options.StepBackMode == StepBackMode.None)
            throw new StepBackNotEnabledException();

        if (_stepBackContexts == null || _stepBackContexts.Count == 0)
            throw new StepBackNotEnabledException();

        var entered =
            (State is ExecutionState.Paused or ExecutionState.PausedBreakpoint or ExecutionState.PausedException)
            && await _runSemaphore.WaitAsync(enterTimeout);

        if (!entered)
        {
            _logger.LogTrace("Execution {Id}: Attempt to step while running.", _executionId);

            throw new InvalidOperationException("Cannot step, execution is running.");
        }

        var context = _stepBackContexts.Pop();
        Engine.RestoreContext(context);

        this.DetermineCurrentStopPositions();
        _runSemaphore.Release();

        State = ExecutionState.Paused;

        await this.SendEvent(new StoppedEvent()
        {
            Description = "Stepped back",
            Reason = StoppedEventReason.Step,
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    public Task StepOut(int enterTimeout = Timeout.Infinite)
    {
        // TODO: use for 'getting out of exceptions'?
        throw new NotImplementedException();
    }

    public Task Pause()
    {
        LastStopCause = StopCause.ExternalPause;
        Engine.EmuStop();

        return Task.CompletedTask;
    }

    public Task Terminate()
    {
        Engine.EmuStop();

        return Task.CompletedTask;
    }

    #endregion

    #region Helper methods

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [MemberNotNull(nameof(_exe), nameof(_segments), nameof(_debugProvider), nameof(LineResolver))]
    private void CheckLoaded()
    {
        // Iff the rest of this code works as intended, this could be cut down only to _exe == null
        if (_exe == null || _segments == null || _debugProvider == null || LineResolver == null)
            throw new InvalidOperationException("Executable not loaded.");
    }

    /// <summary>
    /// Configures the exit addresses on which Unicorn stops its execution.
    /// The exits always include the last instruction address and the text section end address from the executable.
    /// If <see cref="_breakpointExitsDisabled"/> is false, they also include the breakpoint addresses.
    /// </summary>
    private void MakeExits()
    {
        if (_exe == null)
        {
            Engine.SetExits(ReadOnlySpan<ulong>.Empty, 0);

            return;
        }

        var exitsCount = _breakpointExitsDisabled ? 2 : (_currentBreakpoints.Count + 2);
        Span<ulong> exits = stackalloc ulong[exitsCount];
        var i = 0;

        if (!_breakpointExitsDisabled)
        {
            // Breakpoints
            foreach (var (_, breakpoint) in _currentBreakpoints)
            {
                exits[i++] = breakpoint.Address;
            }
        }

        exits[i++] = _exe.LastInstructionAddress + 4;
        exits[i] = _exe.TextSectionEndAddress; // Is this desirable?

        Engine.SetExits(exits);
    }

    private async Task SendEvent<T>(T @event) where T : IProtocolEvent
    {
        await _mediator.Send(new EngineEvent<T>(this, @event));
    }

    internal async Task LogDebugConsole(string message, bool showLine = false, OutputEventGroup? group = null)
    {
        await this.SendEvent(new OutputEvent()
        {
            Category = OutputEventCategory.Console,
            Line = (showLine && _exe != null) ? _debugProvider.LineToClient(CurrentStopLine) : null,
            Output = message == string.Empty ? string.Empty : (message + "\n"),
            Source = (showLine && _exe != null && CurrentStopSourceIndex != -1)
                ? (await _debugProvider.GetSource(CurrentStopSourceIndex, _exe.Sources[CurrentStopSourceIndex]))
                : null,
            Group = group
        });
    }

    private async Task ExitOnTimeout()
    {
        LastStopCause = StopCause.TimeoutOrExternalCancellation;

        try
        {
            await this.HandleStopCause();
        }
        finally
        {
            _runSemaphore.Release();
        }
    }

    private async Task HandleEmulatedOutputBuffer()
    {
        var emuOut = _emulatedOut.ToString();
        _emulatedOut.GetStringBuilder().Clear();
        if (emuOut.Length != 0)
        {
            await this.SendEvent(new OutputEvent()
            {
                Category = OutputEventCategory.StandardOutput,
                Output = emuOut
            });
        }
    }

    #endregion

    public void Dispose()
    {
        // TODO
        _runSemaphore.Dispose();
        _configurationDoneEvent.Dispose();

        Engine.Dispose();
    }
}
