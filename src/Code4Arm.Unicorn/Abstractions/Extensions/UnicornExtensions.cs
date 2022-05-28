// UnicornExtensions.cs
// Author: Ondřej Ondryáš

using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;
using Code4Arm.Unicorn.Abstractions.Enums;

namespace Code4Arm.Unicorn.Abstractions.Extensions;

public static class UnicornExtensions
{
    /// <summary>
    /// Reads a null-terminated 'C-string' from the emulated memory. 
    /// </summary>
    /// <param name="unicorn">The Unicorn instance.</param>
    /// <param name="address">The address of the string's beginning.</param>
    /// <param name="maxLength">The maximum number of bytes to read before an exception is thrown.</param>
    /// <param name="maxAddress">The maximum address where a read can start. Defaults to <see cref="ulong.MaxValue"/>.</param>
    /// <param name="encoding">The encoding to decode the memory bytes with. If null, <see cref="Encoding.UTF8"/> is used.</param>
    /// <returns></returns>
    /// <exception cref="OverflowException">No null terminator found after reading <paramref name="maxLength"/> bytes,
    /// or <see cref="maxAddress"/> exceeded.</exception>
    public static string MemReadCString(this IUnicorn unicorn, ulong address, int maxLength = 256,
        ulong maxAddress = ulong.MaxValue, Encoding? encoding = null)
    {
        if (maxLength <= 0)
            throw new ArgumentOutOfRangeException(nameof(maxLength));

        const int bufferLength = 16;
        const int maxStackAlloc = 128;

        encoding ??= Encoding.UTF8;

        Span<byte> buffer = stackalloc byte[bufferLength];
        var size = -bufferLength;
        var found = false;

        while (!found)
        {
            size += bufferLength;

            if (size >= maxLength)
                throw new OverflowException($"No null terminator found after reading {size} bytes.");

            var currentAddress = address + (ulong)size;

            if (currentAddress >= maxAddress)
                throw new OverflowException("No null terminator found before reaching the maximum address.");

            var toRead = (int) Math.Min(bufferLength, maxAddress - currentAddress);
            unicorn.MemRead(currentAddress, buffer, (nuint)toRead);

            for (var i = 0; i < toRead; i++)
            {
                if (buffer[i] == 0)
                {
                    size += i;
                    found = true;

                    break;
                }
            }
        }
        
        if (size < bufferLength)
            return encoding.GetString(buffer[..size]);

        if (size >= maxStackAlloc)
        {
            var target = ArrayPool<byte>.Shared.Rent(size);
            unicorn.MemRead(address, target, (nuint)size);
            var ret = encoding.GetString(target, 0, size);
            ArrayPool<byte>.Shared.Return(target);

            return ret;
        }
        else
        {
            Span<byte> target = stackalloc byte[size];
            unicorn.MemRead(address, target);

            return encoding.GetString(target);
        }
    }

    /// <summary>
    /// Reads a value of type <typeparamref name="T"/> from the emulated memory.
    /// No byte order conversion is performed.
    /// </summary>
    /// <param name="unicorn">The Unicorn instance.</param>
    /// <param name="address">The start address.</param>
    /// <typeparam name="T">The type of value to read.</typeparam>
    /// <returns>A value of type <typeparamref name="T"/> read from the emulated memory.</returns>
    public static unsafe T MemReadDirect<T>(this IUnicorn unicorn, ulong address) where T : unmanaged
    {
        var size = sizeof(T);
        Span<byte> result = stackalloc byte[size];
        unicorn.MemRead(address, result, (nuint)size);
        var resultCast = MemoryMarshal.Cast<byte, T>(result);

        return resultCast[0];
    }

    /// <summary>
    /// Reads a value of type <typeparamref name="T"/> from the emulated memory.
    /// Performs byte order conversion between the hosting system and the emulated one.
    /// </summary>
    /// <param name="unicorn">The Unicorn instance.</param>
    /// <param name="address">The start address.</param>
    /// <typeparam name="T">The type of value to read.</typeparam>
    /// <returns>A value of type <typeparamref name="T"/> read from the emulated memory.</returns>
    public static unsafe T MemReadSafe<T>(this IUnicorn unicorn, ulong address) where T : unmanaged
    {
        var localLe = BitConverter.IsLittleEndian;
        var unicornLe = (unicorn.CurrentMode & (int)EngineMode.BigEndian) == 0;
        var size = sizeof(T);

        if (localLe == unicornLe || size == 1)
            return MemReadDirect<T>(unicorn, address);

        Span<byte> result = stackalloc byte[size];
        unicorn.MemRead(address, result, (nuint)size);

        result.Reverse();
        var resultCast = MemoryMarshal.Cast<byte, T>(result);

        return resultCast[0];
    }

    /// <summary>
    /// Writes a value of type <typeparamref name="T"/> to the emulated memory.
    /// No byte order conversion is performed so the data is written with the hosting system's byte order.
    /// </summary>
    /// <param name="unicorn">The Unicorn instance.</param>
    /// <param name="address">The start address.</param>
    /// <param name="value">The value.</param>
    /// <typeparam name="T">The type of value to write.</typeparam>
    public static unsafe void MemWriteDirect<T>(this IUnicorn unicorn, ulong address, T value)
        where T : unmanaged
    {
        MemWriteDirect(unicorn, address, value, (nuint)sizeof(T));
    }

    /// <summary>
    /// Writes a value of type <typeparamref name="T"/> to the emulated memory.
    /// No byte order conversion is performed so the data is written with the hosting system's byte order.
    /// </summary>
    /// <param name="unicorn">The Unicorn instance.</param>
    /// <param name="address">The start address.</param>
    /// <param name="value">The value.</param>
    /// <param name="targetSize">The maximum number of bytes to write.</param>
    /// <typeparam name="T">The type of value to write.</typeparam>
    public static void MemWriteDirect<T>(this IUnicorn unicorn, ulong address, T value, nuint targetSize)
        where T : unmanaged
    {
        var valueSpan = MemoryMarshal.CreateReadOnlySpan(ref value, 1);
        var bytes = MemoryMarshal.Cast<T, byte>(valueSpan);

        unicorn.MemWrite(address, bytes, targetSize);
    }

    /// <summary>
    /// Writes a value of type <typeparamref name="T"/> to the emulated memory.
    /// Performs byte order conversion so the data is always written with the emulated system's byte order.
    /// </summary>
    /// <param name="unicorn">The Unicorn instance.</param>
    /// <param name="address">The start address.</param>
    /// <param name="value">The value.</param>
    /// <typeparam name="T">The type of value to write.</typeparam>
    public static unsafe void MemWriteSafe<T>(this IUnicorn unicorn, ulong address, T value)
        where T : unmanaged
    {
        MemWriteSafe(unicorn, address, value, (nuint)sizeof(T));
    }

    /// <summary>
    /// Writes a value of type <typeparamref name="T"/> to the emulated memory.
    /// Performs byte order conversion so the data is always written with the emulated system's byte order.
    /// </summary>
    /// <param name="unicorn">The Unicorn instance.</param>
    /// <param name="address">The start address.</param>
    /// <param name="value">The value.</param>
    /// <param name="targetSize">The maximum number of bytes to write.</param>
    /// <typeparam name="T">The type of value to write.</typeparam>
    public static unsafe void MemWriteSafe<T>(this IUnicorn unicorn, ulong address, T value, nuint targetSize)
        where T : unmanaged
    {
        var localLe = BitConverter.IsLittleEndian;
        var unicornLe = (unicorn.CurrentMode & (int)EngineMode.BigEndian) == 0;
        var size = sizeof(T);

        if (localLe == unicornLe || size == 1)
        {
            MemWriteDirect(unicorn, address, value, targetSize);

            return;
        }

        Span<byte> bytes = stackalloc byte[size];
        MemoryMarshal.Write(bytes, ref value);

        bytes.Reverse();
        unicorn.MemWrite(address, bytes, targetSize);
    }
}
