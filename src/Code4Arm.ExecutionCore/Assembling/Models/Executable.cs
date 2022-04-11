// Executable.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Files.Abstractions;
using ELFSharp.ELF;
using ELFSharp.ELF.Sections;

namespace Code4Arm.ExecutionCore.Assembling.Models;

public class Executable
{
    private List<AssembledObject> _sourceObjects;
    private List<MemorySegment> _segments;
    private Dictionary<uint, BoundFunctionSimulator>? _functionSimulators;

    private ELF<uint> _elf;
    public IReadOnlyList<MemorySegment> Segments => _segments;
    public IAsmProject Project { get; }

    public uint StartAddress { get; private set; }
    public uint EndAddress { get; private set; }

    internal Executable(IAsmProject project, ELF<uint> elf, List<AssembledObject> sourceObjects,
        IEnumerable<BoundFunctionSimulator>? functionSimulators)
    {
        this.Project = project;
        
        _elf = elf;
        _sourceObjects = sourceObjects;
        _segments = new List<MemorySegment>(elf.Segments.Count + 2); // +2 for stack and trampoline

        if (functionSimulators != null)
        {
            _functionSimulators = functionSimulators
                .OrderBy(f => f.Address)
                .ToDictionary(f => f.Address, f => f);

            if (_functionSimulators.Count == 0)
                _functionSimulators = null;
        }

        this.MakeSegments();
        this.CalculateAddresses();
    }

    private void MakeSegments()
    {
        for (var i = 0; i < _elf.Segments.Count; i++)
        {
            var memorySegment = new MemorySegment(_elf, i);
            _segments.Add(memorySegment);
        }
    }

    private void CalculateAddresses()
    {
        var symbols = _elf.Sections.FirstOrDefault(s => s.Type == SectionType.SymbolTable);
        if (symbols == null)
        {
            throw new Exception($"ELF of project {this.Project.Name} doesn't contain a symbol table.");
        }
        
        if (_elf.TryGetSection(".text", out var textSection))
        {
            this.StartAddress = textSection.LoadAddress;
            
        }
    }
}
