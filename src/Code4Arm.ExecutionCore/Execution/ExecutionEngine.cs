// ExecutionEngine.cs
// Author: Ondřej Ondryáš

using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text;
using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Dwarf;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Debugger;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionCore.Execution.ExecutionStateFeatures;
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
        ExternalTermination,
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
    /// <seealso cref="ClearMemory"/>
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
    private readonly Random _rnd = new();

    private readonly Dictionary<uint, AddressBreakpoint> _currentBreakpoints = new();
    private readonly Dictionary<uint, AddressBreakpoint> _currentInstructionBreakpoints = new();
    private readonly Dictionary<uint, AddressBreakpoint> _currentBasicBreakpoints = new();
    private readonly Dictionary<uint, UnicornHookRegistration> _currentLogPoints = new();

    private readonly List<UnicornHookRegistration> _strictAccessHooks = new();
    private readonly Stack<IUnicornContext>? _stepBackContexts;

    private readonly StringBuilder _emulatedInputBuffer = new();
    private readonly object _emulatedInputLocker = new();

    private readonly HeapFeature _heapFeature;

    private Executable? _exe;
    private List<MemorySegment>? _segments;
    private MemorySegment? _stackSegment;
    private ExecutionOptions _options;
    private CancellationTokenSource? _currentCts;
    private UnicornHookRegistration _trampolineHookRegistration;
    private bool _firstRun = true;
    private bool _breakpointExitsDisabled;
    private bool _restarting;

    private readonly ManualResetEventSlim _configurationDoneEvent = new(false);
    private readonly ManualResetEventSlim _resetEvent = new(false);
    private readonly ManualResetEventSlim _waitForInputEvent = new(false);
    private readonly ManualResetEventSlim _waitForOutputEvent = new(false);
    private readonly SemaphoreSlim _runSemaphore = new(1, 1);
    private readonly SemaphoreSlim _logPointSemaphore = new(1, 1);

    public ExecutionState State { get; private set; }
    public IExecutableInfo? ExecutableInfo => _exe;
    public IRuntimeInfo? RuntimeInfo => _exe == null ? null : this;
    public IDebugProvider DebugProvider => _debugProvider;
    public IDebugProtocolSourceLocator SourceLocator => _debugProvider;
    public uint StackStartAddress { get; private set; }
    public uint StackSize => _options.StackSize;
    public uint StackTopAddress { get; private set; }
    public uint StackEndAddress { get; private set; }

    public ExecutionOptions Options
    {
        get => _options;
        set
        {
            if (State == ExecutionState.Running || IsPaused)
                throw new InvalidOperationException("Cannot change options while an execution is in progress.");

            _options = value;
        }
    }

    public IReadOnlyList<MemorySegment> Segments =>
        _segments as IReadOnlyList<MemorySegment> ?? ImmutableList<MemorySegment>.Empty;

    public uint ProgramCounter => CurrentPc;

    public IUnicorn Engine { get; }

    private readonly StringWriter _emulatedOut = new();
    public TextWriter EmulatedOutput => _emulatedOut;

    public Task? CurrentExecutionTask { get; private set; }

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
        _heapFeature = new HeapFeature(this);

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

    #region Emulated input

    private CancellationTokenSource SendWaitingForInputReminder()
    {
        var cts = new CancellationTokenSource();
        _ = Task.Run(async () =>
        {
            try
            {
                // ReSharper disable once AccessToDisposedClosure
                await Task.Delay(5000, cts.Token);
            }
            catch
            {
                return;
            }

            var helpSent = Interlocked.Exchange(ref _inputHelpSent, 1);

            await this.LogDebugConsole(helpSent == 0
                ? "The program is waiting for input. You can pass input to it by sending a value starting with > to the Debug Console."
                : "Waiting for input.");
        });

        return cts;
    }

    private string? ReadCharsFromBuffer(int? numberOfChars)
    {
        if (numberOfChars.HasValue && _emulatedInputBuffer.Length >= numberOfChars.Value)
        {
            var retA = _emulatedInputBuffer.ToString(0, numberOfChars.Value);
            _emulatedInputBuffer.Remove(0, numberOfChars.Value);

            return retA;
        }

        if (_emulatedInputBuffer.Length > 0)
        {
            var retA = _emulatedInputBuffer.ToString();
            _emulatedInputBuffer.Clear();

            return retA;
        }

        return null;
    }

    private string? ReadLineFromBuffer()
    {
        if (_emulatedInputBuffer.Length == 0)
            return null;

        var str = _emulatedInputBuffer.ToString();
        var nl = str.IndexOf('\n');

        if (nl == -1)
            return null;

        var ret = str[0..nl];
        _emulatedInputBuffer.Remove(0, nl + 1);

        return ret;
    }

    private int _inputHelpSent = 0;

    public string WaitForEmulatedInput(int? numberOfChars)
    {
        if (numberOfChars is < 1)
            throw new ArgumentException("Argument must be either null or greater than zero.", nameof(numberOfChars));

        lock (_emulatedInputLocker)
        {
            var existing = this.ReadCharsFromBuffer(numberOfChars);

            if (existing != null)
                return existing;
        }

        var cts = this.SendWaitingForInputReminder();

        _currentCts?.Dispose();
        _waitForInputEvent.Wait();

        cts.Cancel();
        cts.Dispose();

        if (LastStopCause == StopCause.ExternalTermination)
            throw new TerminatedException();

        string? ret = null;
        lock (_emulatedInputLocker)
        {
            var requiredChars = numberOfChars ?? 0;

            if (_emulatedInputBuffer.Length >= requiredChars)
                ret = this.ReadCharsFromBuffer(numberOfChars);
        }

        _waitForInputEvent.Reset();

        if (ret == null)
            return this.WaitForEmulatedInput(numberOfChars);

        this.InitTimeout();

        return ret;
    }

    public string WaitForEmulatedInputLine()
    {
        lock (_emulatedInputLocker)
        {
            var existing = this.ReadLineFromBuffer();

            if (existing != null)
                return existing;
        }

        var cts = this.SendWaitingForInputReminder();

        _currentCts?.Dispose();
        _waitForInputEvent.Wait();

        cts.Cancel();
        cts.Dispose();

        if (LastStopCause == StopCause.ExternalTermination)
            throw new TerminatedException();

        string? ret = null;
        lock (_emulatedInputLocker)
        {
            if (_emulatedInputBuffer.Length >= 0)
                ret = this.ReadLineFromBuffer();
        }

        _waitForInputEvent.Reset();

        if (ret == null)
            return this.WaitForEmulatedInputLine();

        this.InitTimeout();

        return ret;
    }

    public void UngetEmulatedInputChar(char c)
    {
        lock (_emulatedInputLocker)
        {
            _emulatedInputBuffer.Insert(0, c);
        }
    }

    public void AcceptEmulatedInput(string input, bool appendNewline)
    {
        lock (_emulatedInputLocker)
        {
            _emulatedInputBuffer.Append(input);
            if (appendNewline)
                _emulatedInputBuffer.AppendLine();
        }

        _waitForInputEvent.Set();
    }

    #endregion

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
    private async Task MakeStackSegment()
    {
        if (_segments == null)
            throw new InvalidOperationException("_segments must be initialized.");

        // StackPlacementOptions has options for both placement and behaviour on restart.
        // Extract the addres options only first.
        var stOpt = _options.StackPlacementOptions;
        var addressOpts = (int)(stOpt & (StackPlacementOptions.FixedAddress |
            StackPlacementOptions.RandomizeAddress | StackPlacementOptions.AlwaysKeepFirstAddress));

        if ((addressOpts & (addressOpts - 1)) != 0) // Has more than one set bit (~ is power of 2)
            throw new InvalidOperationException(
                $"Invalid stack placement options: only one of {StackPlacementOptions.FixedAddress}, {StackPlacementOptions.RandomizeAddress} and {StackPlacementOptions.AlwaysKeepFirstAddress} can be used.");

        uint stackSegmentBegin;

        if (stOpt.HasFlag(StackPlacementOptions.FixedAddress))
        {
            // Forced address (though it will be aligned in MemorySegment's ctor anyway)
            stackSegmentBegin = _options.ForcedStackAddress;
        }
        else if (_stackSegment == null || stOpt.HasFlag(StackPlacementOptions.RandomizeAddress))
        {
            // Randomization enabled or no stack has been created yet
            stackSegmentBegin = this.CheckAndRandomizeAddress(StackSize);
        }
        else if (!stOpt.HasFlag(StackPlacementOptions.AlwaysKeepFirstAddress))
        {
            // Randomization disabled and stack has previously been created ~ use it
            // This is the default behaviour ~ stack address is decided upon once 
            stackSegmentBegin = this.CheckAndRandomizeAddress(StackSize, _stackSegment.StartAddress);
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

        var newStackSegment = new MemorySegment(stackSegmentBegin, StackSize)
        {
            IsStack = true,
            Permissions = MemorySegmentPermissions.Read | MemorySegmentPermissions.Write
        };

        _segments.Add(newStackSegment);

        if (_stackSegment == null)
        {
            _stackSegment = newStackSegment;

            Engine.MemMap(_stackSegment.StartAddress, _stackSegment.Size, _stackSegment.Permissions.ToUnicorn());

            await this.LogSegmentMapped(newStackSegment);

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
            Engine.MemMap(newStackSegment.StartAddress, newStackSegment.Size, newStackSegment.Permissions.ToUnicorn());

            await this.LogSegmentMapped(newStackSegment);

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

    private uint CheckAndRandomizeAddress(uint size, long initial = -1)
    {
        uint stackSegmentBegin;
        bool collision;

        do
        {
            collision = false;

            // If there was a starting address, use it first and set it to value other than -1
            // so that it's not used the next time
            stackSegmentBegin = initial == -1
                ? (uint)_rnd.NextInt64(0, uint.MaxValue - size - 4096)
                : (uint)initial;
            initial = 0;

            stackSegmentBegin -= (stackSegmentBegin % 4096);

            if (_segments == null)
                break;

            foreach (var memorySegment in _segments)
            {
                if (memorySegment.ContainsBlock(stackSegmentBegin, size))
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

        await this.LogDebugConsole($"Loading executable.");

        _segments ??= new List<MemorySegment>(executable.Segments.Count + 2); // stack + heap

        _exe = executable;

        LineResolver = new DwarfLineAddressResolver(_exe.Elf);

        if (_exe != null)
        {
            this.UnmapAllMemory();
            _firstRun = false;
        }

        _heapFeature.InitMemory(_segments);
        await this.MapMemoryFromExecutable();
        this.InitTrampolineHook();

        State = ExecutionState.Ready;
    }

    public TFeature? GetStateFeature<TFeature>() where TFeature : class, IExecutionStateFeature
    {
        var type = typeof(TFeature);

        if (type == typeof(HeapFeature))
            return _heapFeature as TFeature;

        /*
        if (_features.TryGetValue(type, out var feature))
            return (TFeature)feature;*/

        return null;
    }

#pragma warning restore CS8774

    private async Task MapMemoryFromExecutable()
    {
        if (_exe == null || _segments == null)
            throw new ExecutableNotLoadedException();

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

            await this.LogSegmentMapped(segment);

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

                for (var address = segment.ContentsStartAddress; address < segment.ContentsEndAddress; address += 4)
                {
                    Engine.MemWrite(address, jumpBackInstruction);
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

        if (_trampolineHookRegistration != default)
        {
            Engine.RemoveHook(_trampolineHookRegistration);
            _trampolineHookRegistration = default;
        }

        if (trampoline == null)
            return;

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
    private async Task InitMemoryFromExecutable()
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

        // Move stack on restart
        await this.MakeStackSegment();
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

        // Enable NEON/VFP
        var p15 = new Arm.CoprocessorRegister()
        {
            CoprocessorId = 15,
            Is64Bit = 0,
            SecurityState = 0,
            Crn = 1,
            Crm = 0,
            Opcode1 = 0,
            Opcode2 = 2
        };

        // cp10 and cp11 fields in CPACR control access to SIMD/FP
        // MRC P15, 0, Rx, C1, C0, 2
        // ORR Rx, Rx, 0xF00000
        // MCR P15, 0, Rx, C1, C0, 2
        Engine.RegRead(Arm.Register.CP_REG, ref p15);
        p15.Value |= 0xF00000;
        Engine.RegWrite(Arm.Register.CP_REG, p15);

        // MOV Rx, 0x40000000; FMXR FPEXC, R0
        Engine.RegWrite(Arm.Register.FPEXC, 0x40000000);

        // Switch to User mode (16 because of RES1 at bit 4)
        Engine.RegWrite(Arm.Register.CPSR, 16);

        Engine.RegWrite(Arm.Register.SP, StackTopAddress);
    }

    private void UnmapAllMemory()
    {
        if (_segments == null)
            return;

        foreach (var strictAccessHook in _strictAccessHooks)
        {
            strictAccessHook.RemoveHook();
        }

        _strictAccessHooks.Clear();

        foreach (var nativeCodeHookRef in _nativeCodeHooks.Keys)
        {
            Engine.RemoveNativeHook(nativeCodeHookRef);
        }

        _nativeCodeHooks.Clear();

        foreach (var segment in _segments)
        {
            if (segment.IsStack || segment.IsHeap)
                continue;

            Engine.MemUnmap(segment.StartAddress, segment.Size);

            if (segment.IsDirect && segment.DirectHandle != null)
                segment.DirectHandle.DangerousRelease();
        }

        _segments.Clear();
    }

    private void RandomizeMemory(uint start, uint size)
    {
        // The other option is to allocate _size_ bytes worth of memory and do a single write
        // but I prefer this version which takes (many?) more CPU cycles but allocates MaxStackAllocatedSize B max 

        var bufferSize = Math.Min(size, MaxStackAllocatedSize);
        Span<byte> buffer = stackalloc byte[(int)bufferSize];
        var end = start + size;

        for (var address = start; address < end; address += bufferSize)
        {
            _rnd.NextBytes(buffer);
            Engine.MemWrite(address, buffer, Math.Min(bufferSize, end - address));
        }
    }

    internal void ClearMemory(uint start, uint size)
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
            // Send the output buffer first; try to wait until it happens but not too long.
            _waitForOutputEvent.Reset();
            _ = Task.Run(async () => await this.HandleEmulatedOutputBuffer());
            _waitForOutputEvent.Wait(1000);

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
        catch (TerminatedException)
        {
            // intentionally left blank
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

    private void MergeBreakpoints()
    {
        _currentBreakpoints.Clear();
        foreach (var (address, breakpoint) in _currentBasicBreakpoints)
        {
            _currentBreakpoints.TryAdd(address, breakpoint);
        }

        foreach (var (address, breakpoint) in _currentInstructionBreakpoints)
        {
            _currentBreakpoints.TryAdd(address, breakpoint);
        }
    }

    public IEnumerable<Breakpoint> SetBreakpoints(Source file, IEnumerable<SourceBreakpoint> breakpoints)
    {
        this.CheckLoaded();

        if (State == ExecutionState.Running)
        {
            LastStopCause = StopCause.ExternalPause;
            Engine.EmuStop();
        }

        var sourceCompilationPath = _debugProvider.GetCompilationPathForSource(file);
        var sourceObject = _debugProvider.GetObjectForSource(file);

        if (sourceCompilationPath == null || sourceObject == null)
            throw new InvalidSourceException($"Cannot set breakpoints in file {file.Name ?? file.Path}.");

        _currentBasicBreakpoints.Clear();

        foreach (var (_, hook) in _currentLogPoints)
        {
            hook.RemoveHook();
        }

        _currentLogPoints.Clear();

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
            else if (breakpoint.LogMessage != null)
            {
                var hook = Engine.AddCodeHook((_, _, _) =>
                    {
                        _logPointSemaphore.Wait(500);
                        Task.Run(async () =>
                        {
                            try
                            {
                                await this.LogDebugConsole(breakpoint.LogMessage);
                            }
                            catch (Exception e)
                            {
                                _logger.LogError(e, "Cannot send logpoint message.");
                            }
                            finally
                            {
                                _logPointSemaphore.Release();
                            }
                        });
                    },
                    targetAddress, targetAddress + 3);

                _currentLogPoints.Add(targetAddress, hook);
                var addedBreakpoint = new Breakpoint()
                {
                    Line = _debugProvider.LineToClient(targetLine),
                    Source = file,
                    Verified = true,
                    InstructionReference = FormattingUtils.FormatAddress(targetAddress)
                };

                ret.Add(addedBreakpoint);
            }
            else if (_currentBasicBreakpoints.ContainsKey(targetAddress))
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
                // Create a breakpoint with address information and store it in _currentBasicBreakpoints
                var addedBreakpoint = new AddressBreakpoint()
                {
                    Id = targetAddress,
                    Line = _debugProvider.LineToClient(targetLine),
                    Source = file,
                    Verified = true, // TODO: Check if line contains instruction or data? Somehow?
                    InstructionReference = FormattingUtils.FormatAddress(targetAddress),
                    Address = targetAddress
                };

                ret.Add(addedBreakpoint);
                _currentBasicBreakpoints.Add(targetAddress, addedBreakpoint);
            }
        }

        this.MergeBreakpoints();
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

    public async Task<IEnumerable<Breakpoint>> SetInstructionBreakpoints(
        IEnumerable<InstructionBreakpoint> instructionBreakpoints)
    {
        this.CheckLoaded();

        _currentInstructionBreakpoints.Clear();
        var ret = new List<Breakpoint>();

        foreach (var breakpoint in instructionBreakpoints)
        {
            if (!FormattingUtils.TryParseAddress(breakpoint.InstructionReference, out var address))
            {
                ret.Add(new Breakpoint()
                {
                    Verified = false,
                    Message = ExceptionMessages.InvalidMemoryReference
                });
            }

            if (_currentBasicBreakpoints.ContainsKey(address) || _currentInstructionBreakpoints.ContainsKey(address))
            {
                // Breakpoint on the address is already defined
                ret.Add(new Breakpoint()
                {
                    Message =
                        $"Address {FormattingUtils.FormatAddress(address)} already contains a breakpoint.",
                    Verified = false
                });
            }
            else
            {
                // Determine source info
                var (line, sourceIndex) = _debugProvider.GetAddressInfo(address);
                var source = sourceIndex == -1 ? null : await _debugProvider.GetSource(sourceIndex);

                // Create a breakpoint with address information and store it in _currentInstructionBreakpoints
                var addedBreakpoint = new AddressBreakpoint()
                {
                    Id = address,
                    Line = _debugProvider.LineToClient(line),
                    Source = source,
                    Verified = true,
                    InstructionReference = FormattingUtils.FormatAddress(address),
                    Message = FormattingUtils.FormatAddress(address),
                    Address = address
                };

                ret.Add(addedBreakpoint);
                _currentInstructionBreakpoints.Add(address, addedBreakpoint);
            }
        }

        this.MergeBreakpoints();
        this.MakeExits();

        return ret;
    }

    #endregion

    #region Emulation finished logic

    internal int DetermineSourceIndexForAddress(uint address)
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

        if (LastStopCause == StopCause.Interrupt && LastStopData.InterruptNumber == 7)
            pc += 4; // Move line to the instruction after BKPT

        var lineInfo = LineResolver!.GetSourceLine(pc, out var displacement);
        if (displacement != 0 || lineInfo.File == null)
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

    private async Task BreakpointHit(AddressBreakpoint? breakpoint)
    {
        await this.LogDebugConsole("Hit breakpoint.", true);

        State = ExecutionState.PausedBreakpoint;
        CurrentBreakpoint = breakpoint;

        await this.SendEvent(new StoppedEvent()
        {
            Reason = StoppedEventReason.Breakpoint,
            Description = "Breakpoint hit",
            HitBreakpointIds = breakpoint?.Id == null ? null : new Container<long>(breakpoint.Id.Value),
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
                    await this.StartEmulation(CurrentPc, release: false);
                else
                    await this.HandleDataBreakpoint();

                break;
            case StopCause.ExternalTermination:
                await this.HandleExternalTermination();

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

        await this.LogDebugConsole($"Execution finished after reaching {FormattingUtils.FormatAddress(CurrentPc)}.",
            true);

        if (_exe!.DataSequencesStarts.Contains(CurrentPc) && LastStopCause != StopCause.Interrupt)
        {
            await this.LogDebugConsole(
                "The execution ended after reaching a block of data in the text section.\nThis is probably not a correct behaviour.");
        }

        State = ExecutionState.Finished;

        await this.SendEvent(new ExitedEvent() { ExitCode = 0 });
        await Task.Delay(500);
        await this.SendEvent(new TerminatedEvent());

        this.CleanupExecution();
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

    private async Task HandleExternalTermination()
    {
        _logger.LogTrace("Execution {Id}: Terminated.", _executionId);
        await this.LogDebugConsole("Terminated.");

        State = ExecutionState.Ready;

        await this.SendEvent(new TerminatedEvent());
        this.CleanupExecution();
    }

    private void CleanupExecution()
    {
        _currentBreakpoints.Clear();
        _currentBasicBreakpoints.Clear();
        _currentInstructionBreakpoints.Clear();
        _debugProvider.ClearDataBreakpoints();
        _debugProvider.ClearEvaluateVariables();
        _debugProvider.ClearVariables();

        if (_stepBackContexts is { Count: not 0 })
        {
            foreach (var stepBackContext in _stepBackContexts)
            {
                stepBackContext.Dispose();
            }

            _stepBackContexts.Clear();
        }
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
        await this.LogDebugConsole($"Memory address: {FormattingUtils.FormatAddress(LastStopData.InvalidAddress)}");
        await this.LogDebugConsole($"Access type: {LastStopData.AccessType}");
        if (Options.EnableAccurateExecutionTracking)
            await this.LogDebugConsole($"Current PC: {FormattingUtils.FormatAddress(CurrentPc)}");
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
        // TODO: This is a highly temporary and experimental solution for handling a few syscalls.
        // Implement a generic way to handle various syscalls.
        if (LastStopData.InterruptNumber == 2)
        {
            // Software interrupt
            if (LastStopData.InterruptR7 == 1)
            {
                // exit syscall
                await this.EmulationEnded();

                return;
            }
            else if (LastStopData.InterruptR7 == 3)
            {
                // read syscall; r0 = fd, r1 = buf, r2 = count
                var addr = Engine.RegRead<uint>(Arm.Register.R1);
                var size = Engine.RegRead<uint>(Arm.Register.R2);
                var input = this.WaitForEmulatedInput((int)size);
                var bytes = _debugProvider.Options.CStringEncoding.GetBytes(input);
                Engine.MemWrite(addr, bytes, size);
                await this.StartEmulation(CurrentPc, release: false);

                return;
            }
            else if (LastStopData.InterruptR7 == 4)
            {
                // write syscall; r0 = fd, r1 = buf, r2 = count
                var addr = Engine.RegRead<uint>(Arm.Register.R1);
                var size = Engine.RegRead<uint>(Arm.Register.R2);
                var bytes = Engine.MemRead(addr, size);
                var str = _debugProvider.Options.CStringEncoding.GetString(bytes);
                EmulatedOutput.Write(str);
                await this.HandleEmulatedOutputBuffer();
                await this.StartEmulation(CurrentPc, release: false);

                return;
            }
        }

        // Handle BKPT
        if (LastStopData.InterruptNumber == 7)
        {
            LastStopCause = StopCause.Normal;
            await this.BreakpointHit(null);
            CurrentPc += 4; // BKPT keeps PC on the BKPT instruction, move it one instruction forward

            return;
        }

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

    private async Task StartEmulation(uint startAddress, ulong count = 0ul, bool release = true)
    {
        try
        {
            _resetEvent.Reset();
            _logger.LogTrace("Execution {Id}: Starting on {StartAddress:x8}.", _executionId, startAddress);
            if (_debugProvider.Options.ShowRunningAtMessage)
                await this.LogDebugConsole($"Running at {FormattingUtils.FormatAddress(startAddress)}.", true);

            LastStopCause = StopCause.Normal;
            State = ExecutionState.Running;

            CurrentPc = startAddress;
            Engine.EmuStart(startAddress, 0, 0, count);

            if (_currentCts != null)
            {
                _currentCts.Dispose();
                _currentCts = null;
            }

            if (_restarting)
            {
                return;
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
                await this.LogDebugConsole(ExceptionMessages.GeneralError);
                await this.HandleExternalTermination();

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
            if (release)
            {
                _runSemaphore.Release();
                _resetEvent.Set();
            }
        }
    }

    public async Task InitLaunch(bool debug, int enterTimeout = Timeout.Infinite, bool waitForLaunch = true)
    {
        this.CheckLoaded();

        // If the token gets cancelled here, it propagates a OperationCanceledException out of the method
        // which is OK
        var entered = (State is ExecutionState.Ready or ExecutionState.Finished) &&
            await _runSemaphore.WaitAsync(enterTimeout);

        if (!entered || State is not (ExecutionState.Ready or ExecutionState.Finished))
        {
            _logger.LogTrace("Execution {Id}: Attempt to launch when not ready.", _executionId);

            if (entered)
                _runSemaphore.Release();

            throw new InvalidExecutionStateException(ExceptionMessages.InvalidExecutionLaunchState);
        }

        DebuggingEnabled = debug;
        _breakpointExitsDisabled = !debug;

        // Launch semaphore acquired
        try
        {
            await this.InitMemoryFromExecutable();
            this.InitRegisters();
            _heapFeature.ClearAllocatedMemory();
            this.MakeExits();

            LastStopCause = StopCause.Normal;
            this.InitTimeout();
        }
        catch
        {
            _runSemaphore.Release();

            throw;
        }

        try
        {
            var startAddress = _exe.EntryPoint;

            CurrentExecutionTask = Task.Run(async () =>
            {
                try
                {
                    if (waitForLaunch)
                    {
                        try
                        {
                            _configurationDoneEvent.Wait(_currentCts.Token);
                            _configurationDoneEvent.Reset();
                        }
                        catch (OperationCanceledException)
                        {
                            await this.ExitOnTimeout();

                            return;
                        }
                        catch (Exception e)
                        {
                            _logger.LogWarning(e, "Suspicious exception when waiting for Launch.");
                            await this.ExitOnTimeout();

                            return;
                        }
                    }

                    if (_currentCts.IsCancellationRequested)
                    {
                        await this.ExitOnTimeout();

                        return;
                    }

                    await this.SendEvent(new ProcessEvent()
                    {
                        Name = "code4arm-emulation",
                        IsLocalProcess = false,
                        PointerSize = 32,
                        StartMethod = ProcessEventStartMethod.Launch
                    });

                    if (_restarting)
                    {
                        await Task.Delay(500);
                        await this.SendEvent(new ContinuedEvent() { ThreadId = ThreadId, AllThreadsContinued = true });
                        _restarting = false;
                    }
                }
                catch (Exception e)
                {
                    // To make sure the semaphore gets released in all possible situations
                    LastStopCause = StopCause.TimeoutOrExternalCancellation;
                    _runSemaphore.Release();

                    await this.LogDebugConsole(ExceptionMessages.GeneralError);
                    _logger.LogError(e, "Execution {ExecutionId}: Unexpected error when launching.", _executionId);

                    return;
                }

                await this.StartEmulation(startAddress); // StartEmulation must release the semaphore
            }, _currentCts.Token);
        }
        catch (OperationCanceledException)
        {
            await this.ExitOnTimeout();
        }
    }

    [MemberNotNull(nameof(_currentCts))]
    private void InitTimeout()
    {
        _currentCts?.Dispose();
        _currentCts = new CancellationTokenSource();
        _currentCts.CancelAfter(_options.Timeout);
        _currentCts.Token.Register(() =>
        {
            LastStopCause = StopCause.TimeoutOrExternalCancellation;
            Engine.EmuStop(); // If running, propagates to StartEmulation() which releases the semaphore
        });
    }

    public Task Launch()
    {
        _configurationDoneEvent.Set();

        return Task.CompletedTask;
    }

    public async Task Restart(bool debug, int enterTimeout = Timeout.Infinite)
    {
        this.CheckLoaded();

        _restarting = true;

        if (State == ExecutionState.Running)
        {
            LastStopCause = StopCause.ExternalPause;
            Engine.EmuStop();

            if (!_resetEvent.Wait(enterTimeout))
            {
                _logger.LogError("Execution {ExecutionId}: Cannot perform restart (the execution didn't stop).",
                    _executionId);
                await this.LogDebugConsole(ExceptionMessages.GeneralError);
                await this.HandleExternalTermination();
            }
        }

        await Task.Delay(500);

        State = ExecutionState.Ready;
        await this.InitLaunch(debug, enterTimeout, false);
    }

    public async Task GotoTarget(long targetId, int enterTimeout = Timeout.Infinite)
    {
        this.CheckLoaded();

        var address = (uint)targetId;

        if (address < _exe.TextSectionStartAddress || address >= _exe.TextSectionEndAddress || (address % 4) != 0)
            throw new InvalidGotoTargetException();

        var entered = IsPaused && await _runSemaphore.WaitAsync(enterTimeout);

        if (!entered || !IsPaused)
        {
            _logger.LogTrace("Execution {Id}: Attempt to goto while running.", _executionId);

            if (entered)
                _runSemaphore.Release();

            throw new InvalidExecutionStateException(State);
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
        var entered = IsPaused && await _runSemaphore.WaitAsync(enterTimeout);

        if (!entered || !IsPaused)
        {
            _logger.LogTrace("Execution {Id}: Attempt to continue in state {State}.", _executionId, State);

            if (entered)
                _runSemaphore.Release();

            throw new InvalidExecutionStateException(State);
        }

        // Launch semaphore acquired
        try
        {
            if (State == ExecutionState.PausedBreakpoint)
            {
                // Disable breakpoints, move ONE instruction forward and then re-enable breakpoints
                // This must be done so that the instruction we've stopped on is executed
                _breakpointExitsDisabled = true;
                this.MakeExits();

                Engine.EmuStart(CurrentPc, 0, 0, 1);
                // Passing an instruction count enables Unicorn's internal PC tracking code hook
                // so this is fine even if _options.EnableAccurateExecutionTracking is false.
                CurrentPc = Engine.RegRead<uint>(Arm.Register.PC);

                if (DebuggingEnabled)
                {
                    _breakpointExitsDisabled = false;
                    this.MakeExits();
                }
            }
            else if (DebuggingEnabled && _breakpointExitsDisabled)
            {
                // Re-enable breakpoints if they were disabled
                _breakpointExitsDisabled = false;
                this.MakeExits();
            }

            if (Options.StepBackMode == StepBackMode.CaptureOnStep)
            {
                // Dispose of all saved stepback contexts 
                foreach (var stepBackContext in _stepBackContexts!)
                {
                    stepBackContext.Dispose();
                }

                _stepBackContexts.Clear();
            }

            // This goes on more or less same as in InitLaunch()
            LastStopCause = StopCause.Normal;
            this.InitTimeout();
        }
        catch
        {
            _runSemaphore.Release();

            throw;
        }

        var startAddress = CurrentPc;
        try
        {
            CurrentExecutionTask = Task.Run(async () =>
            {
                if (_currentCts.IsCancellationRequested)
                {
                    await this.ExitOnTimeout(); // Releases the semaphore

                    return;
                }

                try
                {
                    await this.SendEvent(new ContinuedEvent()
                    {
                        ThreadId = ThreadId,
                        AllThreadsContinued = true
                    });
                }
                catch (Exception e)
                {
                    // To make sure the semaphore gets released in all possible situations
                    LastStopCause = StopCause.TimeoutOrExternalCancellation;
                    _runSemaphore.Release();

                    await this.LogDebugConsole(ExceptionMessages.GeneralError);
                    _logger.LogError(e, "Execution {ExecutionId}: Unexpected error when continuing.", _executionId);

                    return;
                }

                await this.StartEmulation(startAddress); // StartEmulation must release the semaphore
            }, _currentCts.Token);
        }
        catch (OperationCanceledException)
        {
            await this.ExitOnTimeout();
        }
    }

    public async Task ReverseContinue(int enterTimeout = Timeout.Infinite)
    {
        // This effectively only jumps to the first stored context

        this.CheckLoaded();

        if (_options.StepBackMode == StepBackMode.None)
            throw new StepBackNotEnabledException();

        if (_stepBackContexts == null || _stepBackContexts.Count == 0)
            throw new StepBackNotEnabledException();

        var entered = IsPaused && await _runSemaphore.WaitAsync(enterTimeout);

        if (!entered || !IsPaused)
        {
            _logger.LogTrace("Execution {Id}: Attempt to reverse continue in state {State} or timeout.",
                _executionId, State);

            if (entered)
                _runSemaphore.Release();

            throw new InvalidExecutionStateException(State);
        }

        try
        {
            var context = _stepBackContexts.Last();
            Engine.RestoreContext(context);

            foreach (var stepBackContext in _stepBackContexts)
            {
                stepBackContext.Dispose();
            }

            _stepBackContexts.Clear();

            this.DetermineCurrentStopPositions();
        }
        finally
        {
            _runSemaphore.Release();
        }

        State = ExecutionState.Paused;

        await this.SendEvent(new StoppedEvent()
        {
            Description = "Stepped back",
            Reason = StoppedEventReason.Step,
            ThreadId = ThreadId,
            AllThreadsStopped = true
        });
    }

    public async Task Step(int enterTimeout = Timeout.Infinite)
    {
        this.CheckLoaded();

        var entered = IsPaused && await _runSemaphore.WaitAsync(enterTimeout);

        if (!entered || !IsPaused)
        {
            _logger.LogTrace("Execution {Id}: Attempt to step in state {State}.", _executionId, State);

            if (entered)
                _runSemaphore.Release();

            throw new InvalidExecutionStateException(State);
        }

        try
        {
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
        }
        catch
        {
            _runSemaphore.Release();

            throw;
        }

        // Stepping used to be invoked on the callers thread as it cannot block the thread
        // for too long. However, when stepping into a simulated TEXT INPUT function, this causes deadlock,
        // because the call comes from the SignalR connection thread - so it cannot receive the 'user input'
        // request that would resume the execution. However, I think it is quite wasteful to run a new Task
        // on every step.
        // TODO: Find a way to only transfer execution to another thread if waiting for input should occur.
        var startAddress = CurrentPc;
        CurrentExecutionTask = Task.Run(async () =>
        {
            await this.StartEmulation(startAddress, 1); // StartEmulation must release the semaphore
        });
    }

    public async Task StepBack(int enterTimeout = Timeout.Infinite)
    {
        this.CheckLoaded();

        if (_options.StepBackMode == StepBackMode.None)
            throw new StepBackNotEnabledException();

        if (_stepBackContexts == null || _stepBackContexts.Count == 0)
            throw new StepBackNotEnabledException();

        var entered = IsPaused && await _runSemaphore.WaitAsync(enterTimeout);

        if (!entered || !IsPaused)
        {
            _logger.LogTrace("Execution {Id}: Attempt to step while running.", _executionId);

            if (entered)
                _runSemaphore.Release();

            throw new InvalidExecutionStateException(State);
        }

        try
        {
            var context = _stepBackContexts.Pop();
            Engine.RestoreContext(context);
            context.Dispose();

            this.DetermineCurrentStopPositions();
        }
        finally
        {
            _runSemaphore.Release();
        }

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
        return this.Step(enterTimeout);
    }

    public Task Pause()
    {
        this.CheckLoaded();

        LastStopCause = StopCause.ExternalPause;
        Engine.EmuStop();

        return Task.CompletedTask;
    }

    public async Task Terminate()
    {
        this.CheckLoaded();

        if (State is ExecutionState.Ready or ExecutionState.Finished)
            throw new InvalidExecutionStateException(State);

        if (State is ExecutionState.Running)
        {
            LastStopCause = StopCause.ExternalTermination;
            _waitForInputEvent.Set();
            Engine.EmuStop();
        }
        else
        {
            await this.HandleExternalTermination();
        }
    }

    #endregion

    #region Helper methods

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    [MemberNotNull(nameof(_exe), nameof(_segments), nameof(_debugProvider), nameof(LineResolver))]
    private void CheckLoaded()
    {
        // Iff the rest of this code works as intended, this could be cut down only to _exe == null
        if (_exe == null || _segments == null || _debugProvider == null || LineResolver == null ||
            State == ExecutionState.Unloaded)
            throw new ExecutableNotLoadedException();
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

        var dataSeqStartsCount = _exe.DataSequencesStarts.Length;
        // Text section end + data sequences starts + breakpoints (if not disabled)
        var exitsCount = 1 + dataSeqStartsCount + (_breakpointExitsDisabled ? 0 : _currentBreakpoints.Count);
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

        foreach (var dataSequenceStart in _exe.DataSequencesStarts)
        {
            exits[i++] = dataSequenceStart;
        }

        exits[i] = _exe.TextSectionEndAddress;

        Engine.SetExits(exits);
    }

    /// <summary>
    /// Dispatches a given protocol event using MediatR.
    /// </summary>
    /// <param name="event">The <see cref="IProtocolEvent"/> to dispatch.</param>
    /// <typeparam name="T">The type of the dispatched event.</typeparam>
    internal async Task SendEvent<T>(T @event) where T : IProtocolEvent
    {
        await _mediator.Send(new EngineEvent<T>(this, @event));
    }

    /// <summary>
    /// Logs a message to the Development Console in the client tool (sends an 'output' event). 
    /// </summary>
    /// <remarks>
    /// To end a message group started by <see cref="OutputEventGroup.Start"/>, send an empty message with
    /// <paramref name="group"/> set to <see cref="OutputEventGroup.End"/>.
    /// </remarks>
    /// <param name="message">The message to log.</param>
    /// <param name="showLine">If true, <see cref="CurrentStopLine"/> and <see cref="CurrentStopSourceIndex"/> will be
    /// used to provide the logged message with line and source information.</param>
    /// <param name="group">A hint for organising successive messages.</param>
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

    internal async Task LogSegmentMapped(MemorySegment segment)
    {
        var type = segment switch
        {
            { IsHeap: true } => "heap",
            { IsStack: true } => "stack",
            { IsTrampoline: true } => "function simulators trampoline",
            { IsMMIO: true } => "memory-mapped I/O",
            { IsFromElf: true } => "program data",
            { IsDirect: true } => "host-mapped memory",
            _ => "unknown segment type"
        };

        var msg = $"Mapped memory segment: {type}, permissions {segment.Permissions.ToFlagString()}";
        var addressMsg = $"Segment start:  0x{segment.StartAddress:x}\nSegment end:    0x{segment.EndAddress:x}";
        var contentsMsg =
            $"Contents start: 0x{segment.ContentsStartAddress:x}\nContents end:   0x{segment.ContentsEndAddress:x}";

        await this.LogDebugConsole(msg, false, OutputEventGroup.StartCollapsed);
        await this.LogDebugConsole(addressMsg);
        await this.LogDebugConsole(contentsMsg);

        if (_options.UseStrictMemoryAccess && (segment.StartAddress != segment.ContentsStartAddress ||
                segment.EndAddress != segment.ContentsEndAddress))
        {
            await this.LogDebugConsole(
                "Strict mode enabled: accessing addresses outside the 'contents' range will trigger an exception.");
        }

        await this.LogDebugConsole(string.Empty, false, OutputEventGroup.End);
    }

    /// <summary>
    /// Executes actions corresponding to the <see cref="StopCause.TimeoutOrExternalCancellation"/> stop cause and
    /// releases the execution semaphore. 
    /// </summary>
    /// <seealso cref="InitLaunch"/>
    /// <seealso cref="Continue"/>
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

    /// <summary>
    /// Extracts the contents of the 'emulated output' buffer and sends them over to the client as an 'output' event.
    /// </summary>
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

        _waitForOutputEvent.Set();
    }

    private bool IsPaused =>
        State is ExecutionState.Paused or ExecutionState.PausedBreakpoint or ExecutionState.PausedException;

    #endregion

    public void Dispose()
    {
        _runSemaphore.Dispose();
        _configurationDoneEvent.Dispose();
        _resetEvent.Dispose();
        _logPointSemaphore.Dispose();

        foreach (var nativeCodeHook in _nativeCodeHooks)
        {
            Engine.RemoveNativeHook(nativeCodeHook.Key);
        }

        _nativeCodeHooks.Clear();

        this.CleanupExecution();

        Engine.Dispose();
    }
}
