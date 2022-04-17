// ExecutionEngine.cs
// Author: Ondřej Ondryáš

using System.Buffers;
using System.Collections.Immutable;
using System.Runtime.InteropServices;
using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;
using ELFSharp.ELF;
using OmniSharp.Extensions.DebugAdapter.Protocol.Models;
using OmniSharp.Extensions.DebugAdapter.Protocol.Requests;
using Architecture = Code4Arm.Unicorn.Abstractions.Enums.Architecture;

namespace Code4Arm.ExecutionCore.Execution;

public class ExecutionEngine : IExecutionEngine, ICodeExecutionInfo
{
    internal readonly MemoryStream InputMemoryStream;
    internal readonly MemoryStream OutputMemoryStream;
    private Executable? _exe;
    private List<MemorySegment>? _segments;
    private MemorySegment? _stackSegment;
    private ExecutionOptions _options;
    private Random _rnd = new();
    private readonly ArrayPool<byte> _arrayPool;
    private const int MaxArrayPoolSize = 1024 * 1024;

    public StepBackMode StepBackMode { get; set; }
    public bool EnableStepBackMemoryCapture { get; set; }
    public bool EnableRegisterDataBreakpoints { get; set; }

    public ExecutionState State { get; private set; }
    public ICodeStaticInfo? CodeInfo { get; } // TODO
    public IExecutableInfo? ExecutableInfo => _exe;
    public ICodeExecutionInfo CodeExecutionInfo => this;

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
        => new Unicorn.Unicorn(Architecture.Arm, EngineMode.Arm | EngineMode.V8 | EngineMode.LittleEndian);

    private void MakeStackSegment()
    {
        if (_segments == null)
            throw new InvalidOperationException("_segments must be initialized.");

        var stOpt = _options.StackPlacementOptions;
        var addressOpts = (int)stOpt & ((int)StackPlacementOptions.FixedAddress +
            (int)StackPlacementOptions.RandomizeAddress + (int)StackPlacementOptions.AlwaysKeepFirstAddress);

        if (addressOpts != 0 && (addressOpts & (addressOpts - 1)) == 0) // Has more than one set bit (~ is power of 2)
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

            stackSegmentBegin += (stackSegmentBegin % 4096);

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
            foreach (var segment in Segments)
            {
                if (segment.IsStack)
                    continue;

                Engine.MemUnmap(segment.StartAddress, segment.Size);
            }

            // TODO?
            _segments?.Clear();
        }

        _exe = executable;
        this.InitMemory(true);
    }

    private void InitMemory(bool remap)
    {
        if (_exe == null)
            throw new InvalidOperationException("Cannot initialize memory before an executable is loaded.");

        foreach (var segment in _exe.Segments)
        {
            if (remap)
                Engine.MemMap(segment.StartAddress, segment.Size, segment.Permissions.ToUnicorn());

            if (segment.HasData)
            {
                if (_options.RandomizeExtraAllocatedSpaceContents)
                {
                    if (segment.ContentsStartAddress != segment.StartAddress)
                        this.RandomizeMemory(segment.StartAddress, segment.ContentsStartAddress - segment.StartAddress);

                    if (segment.ContentsEndAddress != segment.EndAddress)
                        this.RandomizeMemory(segment.ContentsEndAddress,
                            segment.EndAddress - segment.ContentsStartAddress);
                }

                var data = segment.GetData();
                Engine.MemWrite(segment.ContentsStartAddress, data);
            }
            else if (segment.IsTrampoline)
            {
                var jumpBackInstruction = new byte[] { 0x1e, 0xff, 0x2f, 0xe1 };
                var span = jumpBackInstruction.AsSpan();

                for (var address = segment.ContentsStartAddress; address < segment.ContentsEndAddress; address += 4)
                {
                    Engine.MemWrite(address, span);
                }
            }
        }
    }

    private void RandomizeMemory(uint start, uint size)
    {
        var rent = size <= MaxArrayPoolSize;
        var data = rent ? _arrayPool.Rent((int)size) : new byte[size];
        _rnd.NextBytes(data);
        Engine.MemWrite(start, data, size);
        if (rent)
            _arrayPool.Return(data);
    }

    private void ClearMemory(uint start, uint size)
    {
        var rent = size <= MaxArrayPoolSize;
        var data = rent ? _arrayPool.Rent((int)size) : new byte[size];
        Engine.MemWrite(start, data, size);
        if (rent)
            _arrayPool.Return(data);
    }

    public void SetDataBreakpoints(IEnumerable<DataBreakpoint> dataBreakpoints)
    {
        throw new NotImplementedException();
    }

    public void SetBreakpoints(SetBreakpointsArguments arguments)
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

    public Task Launch(bool debug, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
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
        throw new NotImplementedException();
    }

    public IEnumerable<DataBreakpointInfoResponse> GetDataBreakpointInfo(string name) =>
        throw new NotImplementedException();

    public EvaluateResponse EvaluateExpression(EvaluateArguments arguments) => throw new NotImplementedException();

    public ExceptionInfoResponse GetLastExceptionInfo() => throw new NotImplementedException();

    public IEnumerable<GotoTarget> GetGotoTargets(GotoTargetsArguments arguments) =>
        throw new NotImplementedException();
}
