// FormattingUtils.cs
// Author: Ondřej Ondryáš

using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

internal static class FormattingUtils
{
    public static string FormatVariable(uint variable, VariableContext context)
    {
        if (context.NumberFormat == VariableNumberFormat.Hex)
            return FormatHex(variable, context.CultureInfo);

        if (context.NumberFormat == VariableNumberFormat.Binary)
            return Convert.ToString(variable, 2);

        if (context.NumberFormat == VariableNumberFormat.Float)
            return Unsafe.As<uint, float>(ref variable).ToString(context.CultureInfo);

        return variable.ToString(context.CultureInfo);
    }

    public static string FormatVariable(int variable, VariableContext context)
    {
        if (context.NumberFormat == VariableNumberFormat.Hex)
            return FormatHex(variable, context.CultureInfo);

        if (context.NumberFormat == VariableNumberFormat.Binary)
            return Convert.ToString(variable, 2);

        if (context.NumberFormat == VariableNumberFormat.Float)
            return Unsafe.As<int, float>(ref variable).ToString(context.CultureInfo);

        return variable.ToString(context.CultureInfo);
    }

    public static string FormatVariable<T>(T variable, VariableContext context) where T : struct
    {
        if (context.NumberFormat == VariableNumberFormat.Hex)
            return FormatHex(variable, context.CultureInfo);

        if (context.NumberFormat == VariableNumberFormat.Binary)
        {
            Span<long> tmp = stackalloc long[1];
            Span<T> tmpTarget = MemoryMarshal.Cast<long, T>(tmp);

            tmp[0] = 0;
            tmpTarget[0] = variable;

            return Convert.ToString(tmp[0], 2);
        }

        if (context.NumberFormat == VariableNumberFormat.Float)
        {
            var size = Marshal.SizeOf<T>();

            if (size == 4)
                return Unsafe.As<T, float>(ref variable).ToString(context.CultureInfo);
            else if (size == 8)
                return Unsafe.As<T, double>(ref variable).ToString(context.CultureInfo);
            else
                throw new ArgumentException("Invalid variable size to format as a float.", nameof(variable));
        }

        return variable.ToString()!;
    }

    public static uint ParseNumber32U(string value, IFormatProvider? formatProvider)
    {
        ReadOnlySpan<char> span;
        var numberStyle = NumberStyles.Integer | NumberStyles.AllowThousands;

        var binary = IsBinaryNumber(value, out var bS);
        var hS = value.StartsWith("0x");
        var hE = value.EndsWith("x") || value.EndsWith("h");

        if (binary)
            return ParseBinary32(value[bS ? (2..) : (..^1)]);

        if (hS || hE)
        {
            span = value.AsSpan()[hS ? (2..) : (..^1)];
            numberStyle = NumberStyles.HexNumber;
        }
        else
        {
            span = value.AsSpan();
        }

        if (uint.TryParse(span, numberStyle, formatProvider, out var u))
            return u;

        if (int.TryParse(span, numberStyle, formatProvider, out var i))
            return Unsafe.As<int, uint>(ref i);

        if (float.TryParse(span, NumberStyles.Float, formatProvider, out var f))
            return Unsafe.As<float, uint>(ref f);

        if (!Equals(formatProvider, CultureInfo.InvariantCulture))
            return ParseNumber32U(value, CultureInfo.InvariantCulture);

        throw new InvalidVariableFormatException(ExceptionMessages.InvalidVariableFormat32);
    }

    public static uint ParseNumber32F(string value, IFormatProvider? formatProvider)
    {
        if (float.TryParse(value, NumberStyles.Float, formatProvider, out var f))
            return Unsafe.As<float, uint>(ref f);

        if (!Equals(formatProvider, CultureInfo.InvariantCulture))
            return ParseNumber32F(value, CultureInfo.InvariantCulture);

        throw new InvalidVariableFormatException(ExceptionMessages.InvalidVariableFormat32Float);
    }

    public static bool IsBinaryNumber(string value, out bool modifierAtStart)
    {
        if (value.StartsWith("0b"))
        {
            modifierAtStart = true;

            return true;
        }

        if (value.EndsWith("b") && !value.StartsWith("0x"))
        {
            modifierAtStart = false;

            return true;
        }

        modifierAtStart = false;

        return false;
    }

    public static ulong ParseNumber64U(string value, IFormatProvider? formatProvider)
    {
        ReadOnlySpan<char> span;
        var numberStyle = NumberStyles.Integer | NumberStyles.AllowThousands;

        var binary = IsBinaryNumber(value, out var bS);
        var hS = value.StartsWith("0x");
        var hE = value.EndsWith("x") || value.EndsWith("h");

        if (binary)
            return ParseBinary64(value[bS ? (2..) : (..^1)]);

        if (hS || hE)
        {
            span = value.AsSpan()[hS ? (2..) : (..^1)];
            numberStyle = NumberStyles.HexNumber;
        }
        else
        {
            span = value.AsSpan();
        }

        if (ulong.TryParse(span, numberStyle, formatProvider, out var u))
            return u;

        if (long.TryParse(span, numberStyle, formatProvider, out var i))
            return Unsafe.As<long, ulong>(ref i);

        if (double.TryParse(span, NumberStyles.Float, formatProvider, out var f))
            return Unsafe.As<double, ulong>(ref f);

        if (!Equals(formatProvider, CultureInfo.InvariantCulture))
            return ParseNumber64U(value, CultureInfo.InvariantCulture);

        throw new InvalidVariableFormatException(
            "Invalid format. Expected 64b integer (decimal; hex, prefixed with 0x; or binary, prefixed with 0b) or float (32b floating-point number).");
    }

    public static ulong ParseNumber64F(string value, IFormatProvider? formatProvider)
    {
        if (double.TryParse(value, NumberStyles.Float, formatProvider, out var d))
            return Unsafe.As<double, uint>(ref d);

        if (!Equals(formatProvider, CultureInfo.InvariantCulture))
            return ParseNumber64F(value, CultureInfo.InvariantCulture);

        throw new InvalidVariableFormatException(ExceptionMessages.InvalidVariableFormat64Float);
    }

    public static string FormatHex<T>(T variable, CultureInfo cultureInfo) where T : struct
    {
        return variable switch
        {
            sbyte x => x < 0 ? $"-0x{(-x):x}" : $"0x{x:x}",
            short x => x < 0 ? $"-0x{(-x):x}" : $"0x{x:x}",
            int x => x < 0 ? $"-0x{(-x):x}" : $"0x{x:x}",
            long x => x < 0 ? $"-0x{(-x):x}" : $"0x{x:x}",
            float x => x.ToString(cultureInfo),
            double x => x.ToString(cultureInfo),
            _ => string.Format(cultureInfo, "0x{0:x}", variable)
        };
    }

    public static uint ParseBinary32(ReadOnlySpan<char> s)
    {
        uint value = 0;

        if (s.Length > 32)
            throw new InvalidVariableFormatException(ExceptionMessages.InvalidVariableFormat32Binary);

        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c == '1')
            {
                value |= 1;
            }
            else if (c != '0')
            {
                throw new InvalidVariableFormatException(ExceptionMessages.InvalidVariableFormat32Binary);
            }

            if (i != s.Length - 1)
                value <<= 1;
        }

        return value;
    }

    public static ulong ParseBinary64(ReadOnlySpan<char> s)
    {
        ulong value = 0;

        if (s.Length > 64)
            throw new InvalidVariableFormatException(ExceptionMessages.InvalidVariableFormat64Binary);

        for (var i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c == '1')
            {
                value |= 1;
            }
            else if (c != '0')
            {
                throw new InvalidVariableFormatException(ExceptionMessages.InvalidVariableFormat64Binary);
            }

            if (i != s.Length - 1)
                value <<= 1;
        }

        return value;
    }
}
