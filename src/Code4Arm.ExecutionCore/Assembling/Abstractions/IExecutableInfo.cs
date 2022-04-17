// IExecutableInfo.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Models;

namespace Code4Arm.ExecutionCore.Assembling.Abstractions;

public interface IExecutableInfo
{
    public uint EntryPoint { get; }
    public uint LastInstructionAddress { get; }
    public bool StartSymbolDefined { get; }

    public uint TextSectionStartAddress { get; }
    public uint TextSectionEndAddress { get; }

    public IReadOnlyList<MemorySegment> Segments { get; }

    public Dictionary<uint, BoundFunctionSimulator>? FunctionSimulators { get; }
}
