// Executable.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Assembling.Models;

public class Executable
{
    private List<MemorySegment> _segments;
    public IReadOnlyList<MemorySegment> Segments => _segments;
    
    public uint StartAddress { get; }
    public uint StackTopAddress { get; }
}
