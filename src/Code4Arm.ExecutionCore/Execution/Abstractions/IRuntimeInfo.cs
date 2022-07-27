// IRuntimeInfo.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Models;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

/// <summary>
/// Represents a container of runtime-related information emitted by an <see cref="IExecutionEngine"/>
/// after a program has been loaded or run. 
/// </summary>
public interface IRuntimeInfo
{
    uint StackStartAddress { get; }
    uint StackSize { get; }
    uint StackTopAddress { get; }
    uint StackEndAddress { get; }
    IReadOnlyList<MemorySegment> Segments { get; }
    uint ProgramCounter { get; }
}
