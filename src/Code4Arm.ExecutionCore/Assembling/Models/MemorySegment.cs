// MemorySegment.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using System.Runtime.InteropServices;
using ELFSharp.ELF;
using ELFSharp.ELF.Segments;

namespace Code4Arm.ExecutionCore.Assembling.Models;

public class MemorySegment : IDisposable
{
    private readonly byte[]? _data;

    public bool IsDirect { get; }
    public SafeHandle? DirectHandle { get; }
    public bool HasData { get; }

    public uint StartAddress { get; }
    public uint Size { get; }
    public uint EndAddress { get; }

    public uint ContentsStartAddress { get; }
    public uint ContentsSize { get; }
    public uint ContentsEndAddress { get; }

    public bool IsFromElf { get; }
    public ELF<uint>? Elf { get; }
    public Segment<uint>? ElfSegment { get; }

    public MemorySegmentPermissions Permissions { get; init; }
    public bool HasBssSection { get; init; }
    public uint BssStart { get; init; }
    public uint BssEnd { get; init; }

    public bool IsTrampoline { get; init; }
    public bool IsStack { get; init; }
    public bool IsHeap { get; init; }

    // ReSharper disable once InconsistentNaming
    public bool IsMMIO { get; init; }

    public MemorySegment(uint contentsStartAddress, uint contentsSize)
    {
        ContentsStartAddress = contentsStartAddress;
        ContentsSize = contentsSize;
        ContentsEndAddress = contentsStartAddress + contentsSize;

        StartAddress = AlignStartAddress(ContentsStartAddress);
        Size = AlignSize(ContentsSize, StartAddress, ContentsStartAddress);
        EndAddress = StartAddress + Size;

        HasData = false;
        IsDirect = false;
    }

    public MemorySegment(ELF<uint> elf, int segmentIndex)
        : this(elf.Segments[segmentIndex].Address, elf.Segments[segmentIndex].Size)
    {
        IsFromElf = true;
        Elf = elf;
        ElfSegment = elf.Segments[segmentIndex];
        Permissions = ElfSegment.Flags.ToLocal();

        HasData = true;
        IsDirect = false;
    }

    public MemorySegment(SafeHandle handle, uint startAddress, uint size, MemorySegmentPermissions permissions)
        : this(startAddress, size)
    {
        IsFromElf = false;
        Permissions = permissions;

        HasData = false;
        IsDirect = true;

        DirectHandle = handle;
    }

    public MemorySegment(byte[] data, uint startAddress, MemorySegmentPermissions permissions)
        : this(startAddress, (uint)data.Length)
    {
        IsFromElf = false;
        Permissions = permissions;

        HasData = true;
        IsDirect = false;

        _data = data;
    }

    private static uint AlignStartAddress(uint address)
        => (address / 4096) * 4096;

    private static uint AlignSize(uint size, uint memoryStartAddress, uint contentsStartAddress)
        => (((size + (contentsStartAddress - memoryStartAddress)) / 4096) + ((size % 4096 == 0) ? 0u : 1u)) * 4096;

    public byte[] GetData()
    {
        if (!HasData)
            throw new InvalidOperationException("Cannot get data for segment with no data.");

        if (_data != null)
            return _data;

        if (ElfSegment == null)
            throw new Exception("Invalid segment state.");

        return ElfSegment.GetMemoryContents();
    }

    public bool ContainsAddress(uint address)
    {
        return address >= StartAddress && address < EndAddress;
    }

    public bool ContainsBlock(uint address, uint size)
    {
        var end = address + size;

        return ((address >= StartAddress && address < EndAddress) || (end > StartAddress && end < EndAddress)
            || (address < StartAddress && end > EndAddress));
    }

    public void Dispose()
    {
        DirectHandle?.Dispose();
    }
}
