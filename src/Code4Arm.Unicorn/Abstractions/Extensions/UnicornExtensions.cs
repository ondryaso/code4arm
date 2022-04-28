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
    /// Reads a zero-terminated 'C-string' from the virtual memory. 
    /// </summary>
    /// <param name="unicorn">The Unicorn instance.</param>
    /// <param name="address">The address of the string's beginning.</param>
    /// <param name="stringBuilder">A <see cref="StringBuilder"/> instance to use when appending retrieved chunks of memory. If null, a new instance is created.</param>
    /// <returns></returns>
    public static string MemReadCString(this IUnicorn unicorn, ulong address, StringBuilder? stringBuilder = null)
    {
        stringBuilder ??= new StringBuilder();

        const int bufferLength = 16;
        Span<byte> buffer = stackalloc byte[bufferLength];

        while (true)
        {
            unicorn.MemRead(address, buffer, bufferLength);

            for (var i = 0; i < bufferLength; i++)
            {
                if (buffer[i] != 0)
                    continue;

                if (i != 0)
                    stringBuilder.Append(Encoding.ASCII.GetString(buffer[..i]));

                return stringBuilder.ToString();
            }

            stringBuilder.Append(Encoding.ASCII.GetString(buffer));
            address += bufferLength;
        }
    }

    public static string MemReadEncodedCString(this IUnicorn unicorn, ulong address, Encoding? encoding = null)
    {
        encoding ??= Encoding.UTF8;

        const int bufferLength = 16;
        Span<byte> buffer = stackalloc byte[bufferLength];

        var stringLength = 0;
        var found = false;

        while (true)
        {
            unicorn.MemRead(address + (ulong)stringLength, buffer, bufferLength);

            for (var i = 0; i < bufferLength; i++)
            {
                if (buffer[i] != 0)
                    continue;

                stringLength += i;
                found = true;

                break;
            }

            if (found)
                break;

            stringLength += bufferLength;
        }

        if (stringLength <= bufferLength)
            return encoding.GetString(buffer[..(stringLength + 1)]);

        var targetArray = ArrayPool<byte>.Shared.Rent(stringLength);
        unicorn.MemRead(address, targetArray, (nuint)stringLength);
        var str = encoding.GetString(targetArray[..(stringLength + 1)]);
        ArrayPool<byte>.Shared.Return(targetArray);

        return str;
    }

    public static unsafe T MemReadDirect<T>(this IUnicorn unicorn, ulong address) where T : unmanaged
    {
        var size = sizeof(T);
        Span<byte> result = stackalloc byte[size];
        unicorn.MemRead(address, result, (nuint)size);
        var resultCast = MemoryMarshal.Cast<byte, T>(result);

        return resultCast[0];
    }

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
}
