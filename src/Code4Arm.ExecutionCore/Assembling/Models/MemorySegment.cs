// MemorySegment.cs
// Author: Ondřej Ondryáš

using System.Runtime.InteropServices;
using ELFSharp.ELF;
using ELFSharp.ELF.Segments;

namespace Code4Arm.ExecutionCore.Assembling.Models;

public class MemorySegment
{
    public bool IsDirect { get; }
    public SafeHandle? DirectHandle { get; }

    private byte[]? _data;
    public bool HasData { get; }

    public uint StartAddress { get; }
    public uint Size { get; }

    public uint ContentsStartAddress { get; }
    public uint ContentsSize { get; }

    public bool IsFromElf { get; }
    public ELF<uint>? Elf { get; }
    public Segment<uint>? ElfSegment { get; }

    private static uint AlignStartAddress(uint address)
        => (address / 4096) * 4096;

    private static uint AlignSize(uint size, uint memoryStartAddress, uint contentsStartAddress)
        => (((size + (contentsStartAddress - memoryStartAddress)) / 4096) + 1) * 4096;

    private MemorySegment(uint contentsStartAddress, uint contentsSize)
    {
        this.ContentsStartAddress = contentsStartAddress;
        this.ContentsSize = contentsSize;

        this.StartAddress = AlignStartAddress(this.ContentsStartAddress);
        this.Size = AlignSize(this.ContentsSize, this.StartAddress, this.ContentsStartAddress);
    }

    public MemorySegment(ELF<uint> elf, int segmentIndex)
        : this(elf.Segments[segmentIndex].Address, elf.Segments[segmentIndex].Size)
    {
        this.IsFromElf = true;
        this.Elf = elf;
        this.ElfSegment = elf.Segments[segmentIndex];

        this.HasData = true;
        this.IsDirect = false;
        _data = null;
    }

    public MemorySegment(SafeHandle handle, uint startAddress, uint size)
        : this(startAddress, size)
    {
        this.IsFromElf = false;

        this.HasData = false;
        this.IsDirect = true;
        this.DirectHandle = handle;
    }

    public MemorySegment(byte[] data, uint startAddress)
        : this(startAddress, (uint)data.Length)
    {
        this.IsFromElf = false;
        this.HasData = true;
        this.IsDirect = false;
        _data = data;
    }

    public byte[] GetData()
    {
        if (!this.HasData)
            throw new InvalidOperationException("Cannot get data for segment with no data.");

        if (_data != null)
            return _data;

        if (this.ElfSegment == null)
            throw new Exception("Invalid segment state.");

        return this.ElfSegment.GetMemoryContents();
    }
}
