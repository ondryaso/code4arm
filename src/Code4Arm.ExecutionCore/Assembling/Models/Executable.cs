// Executable.cs
// Author: Ondřej Ondryáš

using System.Collections.Immutable;
using System.Globalization;
using System.Text.RegularExpressions;
using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Files.Abstractions;
using ELFSharp.ELF;
using ELFSharp.ELF.Sections;
using Microsoft.Extensions.Logging;

namespace Code4Arm.ExecutionCore.Assembling.Models;

public class Executable : IExecutableInfo, IDisposable
{
    private readonly ELF<uint> _elf;
    private readonly ILogger<Executable> _logger;
    private readonly List<MemorySegment> _segments;
    private readonly long[] _textSectionStarts;
    private readonly long[] _dataSectionStarts;

    private string? _filePath;

    private readonly List<AssembledObject> _sourceObjects;
    private readonly ImmutableList<ExecutableSource> _sources;

    public IReadOnlyList<AssembledObject> SourceObjects => _sourceObjects;
    public IReadOnlyList<long> TextSectionStarts => _textSectionStarts;
    public IReadOnlyList<long> DataSectionStarts => _dataSectionStarts;

    public IAsmMakeTarget MakeTarget { get; }
    public ELF<uint> Elf => _elf;

    internal Executable(IAsmMakeTarget makeTarget, string filePath, string linkerOutput, ELF<uint> elf,
        List<AssembledObject> sourceObjects,
        IEnumerable<BoundFunctionSimulator>? functionSimulators, ILogger<Executable> logger)
    {
        MakeTarget = makeTarget;

        _filePath = filePath;
        _elf = elf;
        _sourceObjects = sourceObjects;
        _logger = logger;
        _segments = new List<MemorySegment>(elf.Segments.Count + 1); // Space for the 'trampoline' 
        _sources = sourceObjects
                   .Select(o =>
                       new ExecutableSource(o.SourceFile, o.BuildFilePath, o.SourceVersion, o.SourceFile.ClientPath))
                   .ToImmutableList();

        if (functionSimulators != null)
        {
            FunctionSimulators = functionSimulators
                                 .OrderBy(f => f.Address)
                                 .ToDictionary(f => f.Address, f => f);

            if (FunctionSimulators.Count == 0)
                FunctionSimulators = null;
        }

        this.MakeSegments();
        this.DetermineCodeRange();

        _textSectionStarts = new long[sourceObjects.Count];
        _dataSectionStarts = new long[sourceObjects.Count];
        this.DetermineDataSectionsStarts(linkerOutput);
        this.DetermineTextSectionsStarts(linkerOutput);
    }

    public IReadOnlyList<MemorySegment> Segments => _segments;
    public IReadOnlyList<ExecutableSource> Sources => _sources;

    /// <summary>
    /// The address of the _start symbol. If no such symbol is defined, points to the start of the .text section.
    /// </summary>
    public uint EntryPoint { get; private set; }

    public uint[] DataSequencesStarts { get; private set; }
    public bool StartSymbolDefined { get; private set; }

    public uint TextSectionStartAddress { get; private set; }
    public uint TextSectionEndAddress { get; private set; }

    public Dictionary<uint, BoundFunctionSimulator>? FunctionSimulators { get; }

    /// <summary>
    /// Creates <see cref="MemorySegment"/> definitions based on the segments from the ELF.
    /// If function simulators are defined, creates a 'trampoline' memory segment spanning over their addresses.
    /// </summary>
    private void MakeSegments()
    {
        var hasBss = _elf.TryGetSection(".bss", out var bssSection);
        var bssStart = bssSection?.LoadAddress ?? 0;
        var bssEnd = bssSection?.LoadAddress + bssSection?.Size ?? 0;

        for (var i = 0; i < _elf.Segments.Count; i++)
        {
            var elfSegment = _elf.Segments[i];
            var segStart = elfSegment.Address;
            var segEnd = elfSegment.Address + elfSegment.Size;

            var segmentHasBss = false;
            var segmentBssStart = 0u;
            var segmentBssEnd = 0u;

            if (hasBss)
                if ((bssStart >= segStart && bssStart < segEnd) || (bssEnd > segStart && bssEnd < segEnd)
                    || (bssStart < segStart && bssEnd > segEnd))
                {
                    segmentHasBss = true;
                    segmentBssStart = Math.Max(bssStart, segStart);
                    segmentBssEnd = Math.Min(bssEnd, segEnd);
                }

            var memorySegment = new MemorySegment(_elf, i)
            {
                HasBssSection = segmentHasBss,
                BssStart = segmentBssStart,
                BssEnd = segmentBssEnd
            };

            _segments.Add(memorySegment);
        }

        if (FunctionSimulators != null)
        {
            var trampolineStart = FunctionSimulators.First().Key;
            var trampolineEnd = FunctionSimulators.Last().Key + 4;
            var memorySegment = new MemorySegment(trampolineStart, trampolineEnd - trampolineStart)
                { IsTrampoline = true, Permissions = MemorySegmentPermissions.Execute };

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
            throw new Exception($"ELF of make target {MakeTarget.Name} doesn't contain a symbol table.");

        if (!_elf.TryGetSection(".text", out var textSection))
            throw new Exception($"ELF of make target {MakeTarget.Name} doesn't contain a text section.");

        TextSectionStartAddress = textSection.LoadAddress;
        TextSectionEndAddress = textSection.LoadAddress + textSection.Size;

        var startSymbol = symbolTable.Entries.FirstOrDefault(e => e.Name == "_start");
        if (startSymbol != null)
        {
            StartSymbolDefined = true;
            EntryPoint = startSymbol.Value;
        }
        else
        {
            _logger.LogTrace("ELF of make target {Name} doesn't define the _start symbol.", MakeTarget.Name);
            EntryPoint = textSection.LoadAddress;
        }

        var textSectionEnd = textSection.LoadAddress + textSection.Size - 4;
        var dataSymbolsOrdered = symbolTable.Entries.OrderBy(s => s.Value)
                                            .Where(s => s.Value >= textSection.LoadAddress &&
                                                s.Value <= textSectionEnd && s.Name.StartsWith("$d"))
                                            .Select(s => s.Value);

        DataSequencesStarts = dataSymbolsOrdered.ToArray();
    }

    private static readonly Regex DataSectionRegex = new(@"\.data\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(\S*)$",
        RegexOptions.Multiline);

    private static readonly Regex TextSectionRegex = new(@"\.text\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(\S*)$",
        RegexOptions.Multiline);

    private void DetermineDataSectionsStarts(string linkerOutput)
    {
        linkerOutput = linkerOutput.ReplaceLineEndings("\n");
        var matches = DataSectionRegex.Matches(linkerOutput);
        var starts = matches
                     .Where(m => m.Groups[2].Value != "0" && !string.IsNullOrWhiteSpace(m.Groups[3].Value))
                     .ToDictionary(m => m.Groups[3].Value,
                         m => ulong.Parse(m.Groups[1].Value, NumberStyles.AllowHexSpecifier));

        var i = 0;
        foreach (var source in _sourceObjects)
        {
            if (starts.TryGetValue(source.ObjectFilePath, out var start))
                _dataSectionStarts[i++] = unchecked((uint)(start & 0xFFFFFFFF));
            else
                _dataSectionStarts[i++] = -1;
        }
    }

    private void DetermineTextSectionsStarts(string linkerOutput)
    {
        var matches = TextSectionRegex.Matches(linkerOutput);
        var starts = matches
                     .Where(m => m.Groups[2].Value != "0")
                     .ToDictionary(m => m.Groups[3].Value,
                         m => ulong.Parse(m.Groups[1].Value, NumberStyles.AllowHexSpecifier));

        var i = 0;
        foreach (var source in _sourceObjects)
        {
            if (starts.TryGetValue(source.ObjectFilePath, out var start))
                _textSectionStarts[i++] = unchecked((uint)(start & 0xFFFFFFFF));
            else
                _textSectionStarts[i++] = -1;
        }
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
