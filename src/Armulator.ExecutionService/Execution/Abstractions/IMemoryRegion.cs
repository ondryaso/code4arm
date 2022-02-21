// IMemoryRegion.cs
// Author: Ondřej Ondryáš

namespace Armulator.ExecutionService.Execution.Abstractions;

public interface IMemoryRegion
{
    int Address { get; }
    int Size { get; }
    byte[] Data { get; }
    MemoryType Type { get; }
}
