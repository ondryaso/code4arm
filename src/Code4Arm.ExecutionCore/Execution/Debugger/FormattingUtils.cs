// FormattingUtils.cs
// Author: Ondřej Ondryáš

using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

internal static class FormattingUtils
{
    public static string FormatVariable(uint variable, VariableContext context)
    {
        if (context.NumberFormat == VariableNumberFormat.Hex)
            return FormatHexSigned(variable, context.CultureInfo);

        if (context.NumberFormat == VariableNumberFormat.Binary)
            return Convert.ToString(variable, 2);

        return variable.ToString(context.CultureInfo);
    }

    public static string FormatVariable(int variable, VariableContext context)
    {
        if (context.NumberFormat == VariableNumberFormat.Hex)
            return FormatHexSigned(variable, context.CultureInfo);

        if (context.NumberFormat == VariableNumberFormat.Binary)
            return Convert.ToString(variable, 2);

        return variable.ToString(context.CultureInfo);
    }

    public static string FormatVariable<T>(T variable, VariableContext context) where T : struct
    {
        if (context.NumberFormat == VariableNumberFormat.Hex)
            return FormatHexSigned(variable, context.CultureInfo);

        if (context.NumberFormat == VariableNumberFormat.Binary)
        {
            Span<long> tmp = stackalloc long[1];
            Span<T> tmpTarget = MemoryMarshal.Cast<long, T>(tmp);

            tmp[0] = 0;
            tmpTarget[0] = variable;

            return Convert.ToString(tmp[0], 2);
        }

        return variable.ToString()!;
    }

    public static uint ParseNumber32U(string value, IFormatProvider? formatProvider)
    {
        ReadOnlySpan<char> span;
        var numberStyle = NumberStyles.Integer | NumberStyles.AllowThousands;

        if (value.StartsWith("0x"))
        {
            span = value.AsSpan()[2..];
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

        throw new InvalidVariableFormatException(
            "Invalid format. Expected 32b integer (decimal or hex, prefixed with 0x) or float (32b floating-point number).");
    }

    public static uint ParseNumber32F(string value, IFormatProvider? formatProvider)
    {
        if (float.TryParse(value, NumberStyles.Float, formatProvider, out var f))
            return Unsafe.As<float, uint>(ref f);

        if (!Equals(formatProvider, CultureInfo.InvariantCulture))
            return ParseNumber32F(value, CultureInfo.InvariantCulture);

        throw new InvalidVariableFormatException("Invalid format. Expected 32b float (32b floating-point number).");
    }

    public static ulong ParseNumber64U(string value, IFormatProvider? formatProvider)
    {
        ReadOnlySpan<char> span;
        var numberStyle = NumberStyles.Integer | NumberStyles.AllowThousands;

        if (value.StartsWith("0x"))
        {
            span = value.AsSpan()[2..];
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
            "Invalid format. Expected 64b integer (decimal or hex, prefixed with 0x) or float (32b floating-point number).");
    }

    public static ulong ParseNumber64F(string value, IFormatProvider? formatProvider)
    {
        if (double.TryParse(value, NumberStyles.Float, formatProvider, out var d))
            return Unsafe.As<double, uint>(ref d);

        if (!Equals(formatProvider, CultureInfo.InvariantCulture))
            return ParseNumber64F(value, CultureInfo.InvariantCulture);

        throw new InvalidVariableFormatException("Invalid format. Expected double (64b floating-point number).");
    }

    public static string FormatHexSigned<T>(T variable, CultureInfo cultureInfo) where T : struct
    {
        return variable switch
        {
            sbyte x => x < 0 ? $"-0x{(-x):x}" : $"0x{x:x}",
            short x => x < 0 ? $"-0x{(-x):x}" : $"0x{x:x}",
            int x => x < 0 ? $"-0x{(-x):x}" : $"0x{x:x}",
            long x => x < 0 ? $"-0x{(-x):x}" : $"0x{x:x}",
            float x => x.ToString(cultureInfo),
            _ => string.Format(cultureInfo, "0x{0:x}", variable)
        };
    }
}
