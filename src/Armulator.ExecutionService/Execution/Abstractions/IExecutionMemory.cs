// IExecutionMemory.cs
// Author: Ondřej Ondryáš

namespace Armulator.ExecutionService.Execution.Abstractions;

public interface IExecutionMemory
{
    int TotalSize { get; }
    ReadOnlySpan<byte> this[int position, int length] { get; set; }
    ReadOnlySpan<byte> this[int position] { set; }
    IEnumerable<IMemoryRegion> Regions { get; }
}
