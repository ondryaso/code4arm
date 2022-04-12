// Executable.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Files.Abstractions;
using ELFSharp.ELF;
using ELFSharp.ELF.Sections;
using Microsoft.Extensions.Logging;

namespace Code4Arm.ExecutionCore.Assembling.Models;

public class Executable : IDisposable
{
    private List<AssembledObject> _sourceObjects;
    private readonly ILogger<Executable> _logger;
    private List<MemorySegment> _segments;
    private Dictionary<uint, BoundFunctionSimulator>? _functionSimulators;

    private string? _filePath;
    private ELF<uint> _elf;
    public IReadOnlyList<MemorySegment> Segments => _segments;
    public IAsmProject Project { get; }

    /// <summary>
    /// The address of the _start symbol. If no such symbol is defined, points to the start of the .text section.
    /// </summary>
    public uint EntryPoint { get; private set; }

    public uint LastInstructionAddress { get; private set; }
    public bool StartSymbolDefined { get; private set; }

    internal Executable(IAsmProject project, string filePath, ELF<uint> elf, List<AssembledObject> sourceObjects,
        IEnumerable<BoundFunctionSimulator>? functionSimulators, ILogger<Executable> logger)
    {
        this.Project = project;

        _filePath = filePath;
        _elf = elf;
        _sourceObjects = sourceObjects;
        _logger = logger;
        _segments = new List<MemorySegment>(elf.Segments.Count + 1); // Space for the 'trampoline' 

        if (functionSimulators != null)
        {
            _functionSimulators = functionSimulators
                .OrderBy(f => f.Address)
                .ToDictionary(f => f.Address, f => f);

            if (_functionSimulators.Count == 0)
                _functionSimulators = null;
        }

        this.MakeSegments();
        this.DetermineCodeRange();
    }

    /// <summary>
    /// Creates <see cref="MemorySegment"/> definitions based on the segments from the ELF.
    /// If function simulators are defined, creates a 'trampoline' memory segment spanning over their addresses.
    /// </summary>
    private void MakeSegments()
    {
        var hasBss = _elf.TryGetSection(".bss", out var bssSection);
        var bssStart = bssSection?.LoadAddress ?? 0;
        var bssEnd = (bssSection?.LoadAddress + bssSection?.Size) ?? 0;

        for (var i = 0; i < _elf.Segments.Count; i++)
        {
            var elfSegment = _elf.Segments[i];
            var segStart = elfSegment.Address;
            var segEnd = elfSegment.Address + elfSegment.Size;

            var segmentHasBss = false;
            var segmentBssStart = 0u;
            var segmentBssEnd = 0u;

            if (hasBss)
            {
                if ((bssStart >= segStart && bssStart < segEnd) || (bssEnd > segStart && bssEnd < segEnd)
                                                                || (bssStart < segStart && bssEnd > segEnd))
                {
                    segmentHasBss = true;
                    segmentBssStart = Math.Max(bssStart, segStart);
                    segmentBssEnd = Math.Min(bssEnd, segEnd);
                }
            }

            var memorySegment = new MemorySegment(_elf, i)
            {
                HasBssSection = segmentHasBss,
                BssStart = segmentBssStart,
                BssEnd = segmentBssEnd
            };

            _segments.Add(memorySegment);
        }

        if (_functionSimulators != null)
        {
            var trampolineStart = _functionSimulators.First().Key;
            var trampolineEnd = _functionSimulators.Last().Key + 4;
            var memorySegment = new MemorySegment(trampolineStart, trampolineEnd - trampolineStart)
                { IsTrampoline = true };

            _segments.Add(memorySegment);
        }
    }

    /// <summary>
    /// Determines the values of <see cref="EntryPoint"/> and <see cref="LastInstructionAddress"/>.
    /// </summary>
    /// <remarks>
    /// <see cref="EntryPoint"/> is either the value of a _start symbol, or the first instruction marked with $a
    /// (see ELF for the Arm® Architecture, 5.5.5), or the start of the .text section.
    /// <see cref="LastInstructionAddress"/> is either the address of a $d symbol that comes after the first $a symbol,
    /// or the end of the .text section.
    /// </remarks>
    /// <exception cref="Exception">The ELF doesn't contain a symbol table nor a .text section.</exception>
    private void DetermineCodeRange()
    {
        var symbolTableSection = _elf.Sections.FirstOrDefault(s => s.Type == SectionType.SymbolTable);
        if (symbolTableSection is not SymbolTable<uint> symbolTable)
        {
            throw new Exception($"ELF of project {this.Project.Name} doesn't contain a symbol table.");
        }

        if (!_elf.TryGetSection(".text", out var textSection))
        {
            throw new Exception($"ELF of project {this.Project.Name} doesn't contain a text section.");
        }

        var startSymbol = symbolTable.Entries.FirstOrDefault(e => e.Name == "_start");
        if (startSymbol != null)
        {
            this.StartSymbolDefined = true;
            this.EntryPoint = startSymbol.Value;
        }
        else
        {
            _logger.LogTrace("ELF of project {Name} doesn't define the _start symbol.", this.Project.Name);
            this.EntryPoint = textSection.LoadAddress;
        }

        var textSectionEnd = textSection.LoadAddress + textSection.Size - 4;
        var symbolsOrdered = symbolTable.Entries.OrderBy(s => s.Value);
        var firstASymbol = 0u;

        foreach (var symbol in symbolsOrdered)
        {
            if (symbol.Value < textSection.LoadAddress)
                continue;
            if (symbol.Value > textSectionEnd)
                break;

            if (symbol.Name.StartsWith("$a"))
            {
                if (firstASymbol == 0u)
                {
                    firstASymbol = symbol.Value;

                    if (!this.StartSymbolDefined)
                        this.EntryPoint = firstASymbol;
                }
            }
            else if (symbol.Name.StartsWith("$d"))
            {
                if (firstASymbol != 0u)
                {
                    textSectionEnd = symbol.Value - 4;
                    break;
                }
            }
        }

        this.LastInstructionAddress = textSectionEnd;
    }

    /// <summary>
    /// Deletes the ELF file.
    /// </summary>
    public void Dispose()
    {
        if (_filePath != null)
        {
            var path = _filePath;
            _filePath = null;

            _elf.Dispose();

            try
            {
                _logger.LogTrace("Deleting temporary ELF file.");
                File.Delete(path);
            }
            catch (Exception e)
            {
                _logger.LogWarning(e, "Cannot delete generated ELF file.");
            }
        }
    }
}
