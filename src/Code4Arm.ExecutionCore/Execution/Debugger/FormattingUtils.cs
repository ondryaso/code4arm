// FormattingUtils.cs
// Author: Ondřej Ondryáš

using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Code4Arm.ExecutionCore.Execution.Configuration;

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
        var numberStyle = NumberStyles.Number;

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
        {
            if (uint.TryParse(span, numberStyle, CultureInfo.InvariantCulture, out u))
                return u;

            if (int.TryParse(span, numberStyle, CultureInfo.InvariantCulture, out i))
                return Unsafe.As<int, uint>(ref i);

            if (float.TryParse(span, NumberStyles.Float, CultureInfo.InvariantCulture, out f))
                return Unsafe.As<float, uint>(ref f);
        }

        throw new FormatException();
    }

    public static int ParseNumber32S(string value, IFormatProvider? formatProvider)
    {
        ReadOnlySpan<char> span;
        var numberStyle = NumberStyles.Number;

        if (value.StartsWith("0x"))
        {
            span = value.AsSpan()[2..];
            numberStyle = NumberStyles.HexNumber;
        }
        else
        {
            span = value.AsSpan();
        }
        
        if (int.TryParse(span, numberStyle, formatProvider, out var i))
            return i;

        if (uint.TryParse(span, numberStyle, formatProvider, out var u))
            return Unsafe.As<uint, int>(ref u);

        if (float.TryParse(span, NumberStyles.Float, formatProvider, out var f))
            return Unsafe.As<float, int>(ref f);

        if (!Equals(formatProvider, CultureInfo.InvariantCulture))
        {
            if (int.TryParse(span, numberStyle, CultureInfo.InvariantCulture, out i))
                return i;

            if (uint.TryParse(span, numberStyle, CultureInfo.InvariantCulture, out u))
                return Unsafe.As<uint, int>(ref u);

            if (float.TryParse(span, NumberStyles.Float, CultureInfo.InvariantCulture, out f))
                return Unsafe.As<float, int>(ref f);
        }

        throw new FormatException();
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
