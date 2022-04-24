// IRuntimeInfo.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Models;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public interface IRuntimeInfo
{
    uint StackStartAddress { get; }
    uint StackSize { get; }
    uint StackTopAddress { get; }
    uint StackEndAddress { get; }
    IReadOnlyList<MemorySegment> Segments { get; }
    uint ProgramCounter { get; }
}
