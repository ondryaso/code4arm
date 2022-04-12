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
    
    public MemorySegmentPermissions Permissions { get; }
    
    public bool HasBssSection { get; init; }
    public uint BssStart { get; init; }
    public uint BssEnd { get; init; }
    public bool IsTrampoline { get; init; }

    private static uint AlignStartAddress(uint address)
        => (address / 4096) * 4096;

    private static uint AlignSize(uint size, uint memoryStartAddress, uint contentsStartAddress)
        => (((size + (contentsStartAddress - memoryStartAddress)) / 4096) + 1) * 4096;

    public MemorySegment(uint contentsStartAddress, uint contentsSize)
    {
        this.ContentsStartAddress = contentsStartAddress;
        this.ContentsSize = contentsSize;

        this.StartAddress = AlignStartAddress(this.ContentsStartAddress);
        this.Size = AlignSize(this.ContentsSize, this.StartAddress, this.ContentsStartAddress);

        this.HasData = false;
        this.IsDirect = false;
    }

    public MemorySegment(ELF<uint> elf, int segmentIndex)
        : this(elf.Segments[segmentIndex].Address, elf.Segments[segmentIndex].Size)
    {
        this.IsFromElf = true;
        this.Elf = elf;
        this.ElfSegment = elf.Segments[segmentIndex];
        this.Permissions = this.ElfSegment.Flags.ToLocal();

        this.HasData = true;
        this.IsDirect = false;
    }

    public MemorySegment(SafeHandle handle, uint startAddress, uint size, MemorySegmentPermissions permissions)
        : this(startAddress, size)
    {
        this.IsFromElf = false;
        this.Permissions = permissions;
        
        this.HasData = false;
        this.IsDirect = true;
        
        this.DirectHandle = handle;
    }

    public MemorySegment(byte[] data, uint startAddress, MemorySegmentPermissions permissions)
        : this(startAddress, (uint)data.Length)
    {
        this.IsFromElf = false;
        this.Permissions = permissions;

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
