// DwarfLineAddressResolver.cs
// Author: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) 2022 Ondřej Ondryáš.

using ELFSharp.ELF;
using SharpUtilities;

namespace Code4Arm.ExecutionCore.Dwarf;

/// <summary>
/// This class provides conversion between source line number and address in an executable file for an ELF executable
/// with DWARF debugging data.
/// </summary>
public class DwarfLineAddressResolver
{
    private readonly Dictionary<string, SimpleCache<Dictionary<int, uint>>> _addressCache;
    private readonly SimpleCache<List<uint>> _lineInformationAddressesCache;
    private readonly SimpleCache<List<DwarfLineInformation>> _lineInformationCache;
    private readonly List<DwarfLineNumberProgram> _lineNumberPrograms = new();

    /// <summary>
    /// Creates a new instance of <see cref="DwarfLineAddressResolver"/> for a given loaded ELF executable.
    /// </summary>
    /// <param name="elf">An <see cref="ELF{T}"/> of <see cref="uint"/> type that contains the ELF data.</param>
    public DwarfLineAddressResolver(ELF<uint> elf)
    {
        var image = new ElfImage(elf);
        this.ParseLineNumberPrograms(image.DebugLine, image.NormalizeAddress);

        _lineInformationCache = SimpleCache.Create(() =>
        {
            var result = _lineNumberPrograms
                         .SelectMany(p => p.Files)
                         .SelectMany(f => f.Lines)
                         .ToList();

            result.Sort((l1, l2) => (int)l1.Address - (int)l2.Address);

            return result;
        });

        _lineInformationAddressesCache =
            SimpleCache.Create(() => _lineInformationCache.Value.Select(l => l.Address).ToList());

        _addressCache = new Dictionary<string, SimpleCache<Dictionary<int, uint>>>();
        foreach (var fileInformation in _lineNumberPrograms
                                        .SelectMany(p => p.Files)
                                        .GroupBy(f => f.Path))
        {
            _addressCache.Add(fileInformation.Key,
                SimpleCache.Create(() =>
                {
                    return fileInformation.SelectMany(f => f.Lines)
                                          .OrderBy(l => l.Address)
                                          .DistinctBy(l => l.Line)
                                          .ToDictionary(line => (int)line.Line, line => line.Address);
                }));
        }
    }

    private void ParseLineNumberPrograms(byte[] debugLine,
        Func<uint, uint> addressNormalizer)
    {
        using var debugLineReader = new DwarfMemoryReader(debugLine);

        while (!debugLineReader.IsEnd)
        {
            var program = new DwarfLineNumberProgram(debugLineReader, addressNormalizer);
            _lineNumberPrograms.Add(program);
        }
    }

    /// <summary>
    /// Returns source line information for a given address.
    /// </summary>
    /// <param name="address">The address.</param>
    /// <param name="displacement">The offset of <paramref name="address"/> from the first byte of the corresponding instruction is stored here.</param>
    /// <returns>A <see cref="DwarfLineInformation"/> structure with information about the corresponding source line.
    /// If no such line is found, the default value is returned.</returns>
    public DwarfLineInformation GetSourceLine(uint address, out uint displacement)
    {
        var index = _lineInformationAddressesCache.Value.BinarySearch(address);

        if (index < 0)
            index = ~index;

        if (index >= _lineInformationCache.Value.Count)
            index = _lineInformationCache.Value.Count - 1;

        var addressCached = _lineInformationAddressesCache.Value[index];

        if (addressCached > address && index > 0)
        {
            index--;
            addressCached = _lineInformationAddressesCache.Value[index];
        }

        if (addressCached > address)
        {
            displacement = 0;

            return default;
        }

        var lineCached = _lineInformationCache.Value[index];

        displacement = address - addressCached;

        return lineCached;
    }

    /// <summary>
    /// Returns the executable address corresponding to a given line in a given source file.
    /// </summary>
    /// <param name="sourceName">Name of the source file.</param>
    /// <param name="line">The line in the source file.</param>
    /// <returns>The address in the executable, or <see cref="uint.MaxValue"/> if no such line exists.</returns>
    public uint GetAddress(string sourceName, int line)
    {
        if (!_addressCache.TryGetValue(sourceName, out var addresses))
            return 0;

        return (addresses.Value?.TryGetValue(line, out var address) ?? false) ? address : uint.MaxValue;
    }
}
