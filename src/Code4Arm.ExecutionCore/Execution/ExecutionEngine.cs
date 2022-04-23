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
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;
using Architecture = Code4Arm.Unicorn.Abstractions.Enums.Architecture;

namespace Code4Arm.ExecutionCore.Execution;

public class ExecutionEngine : IExecutionEngine, IRuntimeInfo
{
    private const int MaxArrayPoolSize = 2 * 1024 * 1024;
    private const int MaxStackAllocatedSize = 512;

    internal readonly MemoryStream InputMemoryStream;
    internal readonly MemoryStream OutputMemoryStream;
    private Executable? _exe;
    private List<MemorySegment>? _segments;
    private MemorySegment? _stackSegment;
    private ExecutionOptions _options;
    private Random _rnd = new();
    private readonly ArrayPool<byte> _arrayPool;
    private List<UnicornHookRegistration> _strictAccessHooks = new();
    private CancellationTokenSource? _currentCts;

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

    public IUnicorn Engine { get; }
    public Stream EmulatedInput => InputMemoryStream;
    public Stream EmulatedOutput => OutputMemoryStream;

    public ExecutionEngine(ExecutionOptions options)
    {
        _options = options;

        Engine = this.MakeUnicorn();
        State = ExecutionState.Unloaded;

        InputMemoryStream = new MemoryStream();
        OutputMemoryStream = new MemoryStream();

        // Let's find out if Shared is enough...
        _arrayPool = ArrayPool<byte>.Shared;
    }

    private IUnicorn MakeUnicorn()
        => new Unicorn.Unicorn(Architecture.Arm, EngineMode.Arm | EngineMode.LittleEndian);

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
            this.UnmapAllMemory();

        _exe = executable;
        this.MapMemoryFromExecutable();

        DebugProvider = new DebugProvider(this);

        // TODO: delete this
        this.InitMemoryFromExecutable();
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
    /// Load data of segments from the executable.
    /// </summary>
    /// <remarks>
    /// This is used just before emulation is started. It overwrites the current contents of virtual memory with data
    /// from the executable and zeroes out BSS sections.
    /// </remarks>
    private void InitMemoryFromExecutable()
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
        Console.WriteLine($"STRICT ACCESS HOOK AT {address:x8}");
        Engine.EmuStop();
        // TODO
    }

    public void SetDataBreakpoints(IEnumerable<DataBreakpoint> dataBreakpoints)
    {
        throw new NotImplementedException();
    }

    public void SetBreakpoints(IAsmFile file, IEnumerable<SourceBreakpoint> breakpoints)
    {
        throw new NotImplementedException();
    }

    public void SetFunctionBreakpoints(IEnumerable<FunctionBreakpoint> functionBreakpoints)
    {
        throw new NotImplementedException();
    }

    public void SetInstructionBreakpoints(IEnumerable<InstructionBreakpoint> instructionBreakpoints)
    {
        throw new NotImplementedException();
    }

    private ulong GetCurrentStartAddress()
    {
        return 0;
    }

    public async Task Launch(bool debug, CancellationToken cancellationToken = default)
    {
        this.InitMemoryFromExecutable();

        var startAddress = this.GetCurrentStartAddress();

        _currentCts?.Dispose();
        _currentCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _currentCts.CancelAfter(_options.Timeout);

        try
        {
            await Task.Run(() => { Engine.EmuStart(startAddress, 0, 0, 0); }, _currentCts.Token);
        }
        catch (OperationCanceledException)
        {
            // TODO
            Engine.EmuStop();
        }
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
