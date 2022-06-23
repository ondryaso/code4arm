// DwarfMemoryReader.cs
// Original source: https://github.com/southpolenator/SharpDebug
// Original author: Vuk Jovanovic
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) 2019 Vuk Jovanovic, 2022 Ondřej Ondryáš.

using System.Runtime.InteropServices;

namespace Code4Arm.ExecutionCore.Dwarf;

/// <summary>
/// Simple memory reader that provides specific functionality to read DWARF streams.
/// </summary>
/// <seealso cref="System.IDisposable"/>
internal class DwarfMemoryReader : IDisposable
{
    /// <summary>
    /// The pinned data
    /// </summary>
    private GCHandle _pinnedData;

    /// <summary>
    /// The pointer of pinned data
    /// </summary>
    private IntPtr _pointer;

    /// <summary>
    /// Gets the data buffer.
    /// </summary>
    public byte[] Data { get; }

    /// <summary>
    /// Gets or sets the current position in the stream.
    /// </summary>
    public int Position { get; set; }

    /// <summary>
    /// Gets a value indicating whether stream has reached the end.
    /// </summary>
    /// <value>
    /// <c>true</c> if stream reached the end; otherwise, <c>false</c>.
    /// </value>
    public bool IsEnd => Position >= Data.Length;

    /// <summary>
    /// Initializes a new instance of the <see cref="DwarfMemoryReader"/> class.
    /// </summary>
    /// <param name="data">The data.</param>
    public DwarfMemoryReader(byte[] data)
    {
        Data = data;
        Position = 0;
        _pinnedData = GCHandle.Alloc(data, GCHandleType.Pinned);
        _pointer = _pinnedData.AddrOfPinnedObject();
    }

    /// <summary>
    /// Peeks next byte in the stream.
    /// </summary>
    public byte Peek() => Data[Position];

    /// <summary>
    /// Reads the specified structure from the current position in the stream.
    /// </summary>
    /// <typeparam name="T">Type of the structure to be read</typeparam>
    public T ReadStructure<T>()
    {
        var result = Marshal.PtrToStructure<T>(_pointer + Position);

        Position += Marshal.SizeOf<T>();

        return result;
    }

    /// <summary>
    /// Reads the offset from the current position in the stream.
    /// </summary>
    /// <param name="is64Bit">if set to <c>true</c> offset is 64 bit.</param>
    public int ReadOffset(bool is64Bit) => is64Bit ? (int)this.ReadUlong() : (int)this.ReadUint();

    /// <summary>
    /// Reads the unit length from the current position in the stream.
    /// </summary>
    /// <param name="is64Bit">if set to <c>true</c> length was 64 bit.</param>
    public ulong ReadLength(out bool is64Bit)
    {
        ulong length = this.ReadUint();

        if (length == uint.MaxValue)
        {
            is64Bit = true;
            length = this.ReadUlong();
        }
        else
        {
            is64Bit = false;
        }

        return length;
    }

    /// <summary>
    /// Reads the string from the current position in the stream.
    /// </summary>
    public string ReadString()
    {
        var result = Marshal.PtrToStringAnsi(_pointer + Position);

        Position += result.Length + 1;

        return result;
    }

    /// <summary>
    /// Reads the byte from the current position in the stream.
    /// </summary>
    public byte ReadByte() => Data[Position++];

    /// <summary>
    /// Reads the unsigned short from the current position in the stream.
    /// </summary>
    public ushort ReadUshort()
    {
        var result = (ushort)Marshal.ReadInt16(_pointer, Position);

        Position += 2;

        return result;
    }

    /// <summary>
    /// Reads the unsigned int from the current position in the stream.
    /// </summary>
    public uint ReadUint()
    {
        var result = (uint)Marshal.ReadInt32(_pointer, Position);

        Position += 4;

        return result;
    }

    /// <summary>
    /// Reads the unsigned long from the current position in the stream.
    /// </summary>
    public ulong ReadUlong()
    {
        var result = (ulong)Marshal.ReadInt64(_pointer, Position);

        Position += 8;

        return result;
    }

    /// <summary>
    /// Reads the unsigned long of the specified size from the current position in the stream.
    /// </summary>
    /// <param name="size">The size.</param>
    public ulong ReadUlong(uint size)
    {
        switch (size)
        {
            case 1:
                return this.ReadByte();
            case 2:
                return this.ReadUshort();
            case 4:
                return this.ReadUint();
            case 8:
                return this.ReadUlong();
            default:
                throw new Exception("Unexpected read size");
        }
    }

    /// <summary>
    /// Reads unsigned LEB 128 value from the current position in the stream.
    /// </summary>
    public uint Leb128()
    {
        uint x = 0;
        var shift = 0;

        while ((Data[Position] & 0x80) != 0)
        {
            x |= (uint)((Data[Position] & 0x7f) << shift);
            shift += 7;
            Position++;
        }

        x |= (uint)(Data[Position] << shift);
        Position++;

        return x;
    }

    /// <summary>
    /// Reads signed LEB 128 value from the current position in the stream.
    /// </summary>
    public uint Sleb128()
    {
        var x = 0;
        var shift = 0;

        while ((Data[Position] & 0x80) != 0)
        {
            x |= (Data[Position] & 0x7f) << shift;
            shift += 7;
            Position++;
        }

        x |= Data[Position] << shift;
        if ((Data[Position] & 0x40) != 0)
            x |= -(1 << (shift + 7)); // sign extend
        Position++;

        return (uint)x;
    }

    /// <summary>
    /// Reads the byte block of the specified size from the current position in the stream.
    /// </summary>
    /// <param name="size">The size of block.</param>
    public byte[] ReadBlock(uint size)
    {
        var block = new byte[size];

        Array.Copy(Data, Position, block, 0, block.Length);
        Position += block.Length;

        return block;
    }

    /// <summary>
    /// Reads the byte block of the specified size from the specified position in the stream.
    /// </summary>
    /// <param name="size">The size.</param>
    /// <param name="position">The position.</param>
    public byte[] ReadBlock(uint size, int position)
    {
        var originalPosition = Position;
        Position = position;
        var result = this.ReadBlock(size);
        Position = originalPosition;

        return result;
    }

    /// <summary>
    /// Reads the string from the specified position in the stream.
    /// </summary>
    /// <param name="position">The position.</param>
    public string ReadString(int position)
    {
        var originalPosition = Position;
        Position = position;
        var result = this.ReadString();
        Position = originalPosition;

        return result;
    }

    /// <summary>
    /// Reads the unsigned int from the specified position in the stream.
    /// </summary>
    /// <param name="position">The position.</param>
    public uint ReadUint(int position)
    {
        var originalPosition = Position;
        Position = position;
        var result = this.ReadUint();
        Position = originalPosition;

        return result;
    }

    /// <summary>
    /// Reads the specified structure from the specified position in the stream.
    /// </summary>
    /// <typeparam name="T">Type of the structure to be read.</typeparam>
    /// <param name="position">The position.</param>
    public T ReadStructure<T>(int position)
    {
        var originalPosition = Position;
        Position = position;
        var result = this.ReadStructure<T>();
        Position = originalPosition;

        return result;
    }

    /// <summary>
    /// Performs application-defined tasks associated with freeing, releasing, or resetting unmanaged resources.
    /// </summary>
    public void Dispose()
    {
        _pinnedData.Free();
        _pointer = IntPtr.Zero;
    }
}
