// ElfImage.cs
// Original source: https://github.com/southpolenator/SharpDebug
// Original author: Vuk Jovanovic
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) 2019 Vuk Jovanovic, 2022 Ondřej Ondryáš.

using ELFSharp.ELF;
using ELFSharp.ELF.Sections;
using ELFSharp.ELF.Segments;

namespace Code4Arm.ExecutionCore.Dwarf;

/// <summary>
/// Simple ELF image reader.
/// </summary>
internal class ElfImage
{
    /// <summary>
    /// The ELF interface
    /// </summary>
    private readonly ELF<uint> _elf;

    /// <summary>
    /// Gets the code segment offset.
    /// </summary>
    public uint CodeSegmentOffset { get; }

    /// <summary>
    /// Gets the image load offset.
    /// </summary>
    public uint LoadOffset { get; }

    /// <summary>
    /// Gets the debug data.
    /// </summary>
    public byte[] DebugData => this.LoadSection(".debug_info");

    /// <summary>
    /// Gets the debug data description.
    /// </summary>
    public byte[] DebugDataDescription => this.LoadSection(".debug_abbrev");

    /// <summary>
    /// Gets the debug data strings.
    /// </summary>
    public byte[] DebugDataStrings => this.LoadSection(".debug_str");

    /// <summary>
    /// Gets the debug frame.
    /// </summary>
    public byte[] DebugFrame => this.LoadSection(".debug_frame");

    /// <summary>
    /// Gets the debug line.
    /// </summary>
    public byte[] DebugLine => this.LoadSection(".debug_line");

    /// <summary>
    /// Initializes a new instance of the <see cref="ElfImage"/> class.
    /// </summary>
    /// <param name="elf">The ELF.</param>
    /// <param name="loadOffset">Offset from where image was loaded.</param>
    public ElfImage(ELF<uint> elf, uint loadOffset = 0)
    {
        _elf = elf;
        LoadOffset = loadOffset;

        foreach (var segment in elf.Segments)
        {
            if (segment.Type == SegmentType.ProgramHeader)
            {
                CodeSegmentOffset = segment.Address - (uint)segment.Offset;

                break;
            }
        }
    }

    /// <summary>
    /// Gets address offset within module when it is loaded.
    /// </summary>
    /// <param name="address">Virtual address that points where something should be loaded.</param>
    public uint NormalizeAddress(uint address)
    {
        var section =
            _elf.Sections.FirstOrDefault(s => s.LoadAddress <= address && s.LoadAddress + s.Size > address);

        if (section != null && section.Flags.HasFlag(SectionFlags.Allocatable))
            return address - CodeSegmentOffset + LoadOffset;

        return address - CodeSegmentOffset;
    }

    /// <summary>
    /// Loads the section bytes specified by the name.
    /// </summary>
    /// <param name="sectionName">Name of the section.</param>
    /// <returns>Section bytes.</returns>
    private byte[] LoadSection(string sectionName)
    {
        foreach (ISection section in _elf.Sections)
        {
            if (section.Name == sectionName)
                return section.GetContents();
        }

        return Array.Empty<byte>();
    }

    /// <summary>
    /// Gets the section address after loading into memory.
    /// </summary>
    /// <param name="sectionName">Name of the section.</param>
    /// <returns>Address of section after loading into memory.</returns>
    private uint GetSectionAddress(string sectionName)
    {
        foreach (var section in _elf.Sections)
        {
            if (section.Name == sectionName)
            {
                var loadOffset = section.Flags.HasFlag(SectionFlags.Allocatable) ? LoadOffset : 0;

                return section.Offset + CodeSegmentOffset + loadOffset;
            }
        }

        return uint.MaxValue;
    }
}
