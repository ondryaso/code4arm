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
    /// <summary>
    /// Formats a number according to the configuration in a given <see cref="VariableContext"/>.
    /// </summary>
    /// <remarks>
    /// If <see cref="VariableContext.ForceSigned"/> is true, the call is passed to <see cref="FormatSignedVariable"/>.
    /// If <see cref="VariableContext.NumberFormat"/> is <see cref="VariableNumberFormat.Hex"/>, the call is passed to
    /// <see cref="FormatHex{T}"/>.
    /// If <see cref="VariableContext.NumberFormat"/> is <see cref="VariableNumberFormat.Binary"/>, the number is formatted
    /// in binary, optionally left-padded (controlled by <see cref="DebuggerOptions.PadUnsignedBinaryNumbers"/>.
    /// If <see cref="VariableContext.NumberFormat"/> is <see cref="VariableNumberFormat.Float"/>, the unsigned int's
    /// binary value is interpreted as a float which is formatted accordingly.
    /// </remarks>
    /// <param name="variable">The input number.</param>
    /// <param name="context">A variable context with formatting options.</param>
    /// <param name="actualBinarySize">The maximum bit width of the input number used when padding.</param>
    /// <returns>The formatted number.</returns>
    public static string FormatVariable(uint variable, VariableContext context, int actualBinarySize = 32)
    {
        if (context.ForceSigned)
            return FormatSignedVariable(unchecked((int)variable), context, actualBinarySize);
        
        if (context.NumberFormat == VariableNumberFormat.Hex)
            return FormatHex(variable, context.CultureInfo);

        if (context.NumberFormat == VariableNumberFormat.Binary)
        {
            var ret = Convert.ToString(variable, 2);
            if (context.Options.PadUnsignedBinaryNumbers)
                ret = ret.PadLeft(actualBinarySize, '0');

            return ret;
        }

        if (context.NumberFormat == VariableNumberFormat.Float)
            return Unsafe.As<uint, float>(ref variable).ToString(context.CultureInfo);

        return variable.ToString(context.CultureInfo);
    }

    /// <summary>
    /// Formats a number according to the configuration in a given <see cref="VariableContext"/>.
    /// </summary>
    /// <remarks>
    /// If <see cref="VariableContext.NumberFormat"/> is <see cref="VariableNumberFormat.Hex"/>, the call is passed to
    /// <see cref="FormatHex{T}"/>.
    /// If <see cref="VariableContext.NumberFormat"/> is <see cref="VariableNumberFormat.Binary"/>, the number is
    /// formatted as a left-padded binary. Negative numbers will be formatted as their 2's complement, prefixed with a - sign.
    /// If <see cref="VariableContext.NumberFormat"/> is <see cref="VariableNumberFormat.Float"/>, the int's
    /// binary value is interpreted as a float which is formatted accordingly.
    /// </remarks>
    /// <param name="variable">The input number.</param>
    /// <param name="context">A variable context with formatting options.</param>
    /// <param name="actualBinarySize">The maximum bit width of the input number used when padding.</param>
    /// <returns>The formatted number.</returns>
    public static string FormatSignedVariable(int variable, VariableContext context, int actualBinarySize = 32)
    {
        if (context.NumberFormat == VariableNumberFormat.Hex)
            return FormatHex(variable, context.CultureInfo);

        if (context.NumberFormat == VariableNumberFormat.Binary)
        {
            if (variable < 0)
            {
                var varU = unchecked((uint)variable);
                varU = ~varU;
                varU += 1;

                return "-" + Convert.ToString(varU, 2).PadLeft(actualBinarySize, '0');
            }

            return Convert.ToString(variable, 2).PadLeft(actualBinarySize, '0');
        }

        if (context.NumberFormat == VariableNumberFormat.Float)
            return Unsafe.As<int, float>(ref variable).ToString(context.CultureInfo);

        return variable.ToString(context.CultureInfo);
    }

    /// <summary>
    /// Formats any numeric value according to the configuration in a given <see cref="VariableContext"/>.
    /// </summary>
    /// <remarks>
    /// This method's behaviour is the same as in <see cref="FormatVariable"/> and <see cref="FormatSignedVariable"/>.
    /// </remarks>
    /// <exception cref="ArgumentException"><see cref="VariableContext.NumberFormat"/> is <see cref="VariableNumberFormat.Float"/>
    /// but the target type is not 4 or 8 bytes wide.</exception>
    public static string FormatAnyVariable<T>(T variable, VariableContext context, int singedBinaryPad = -1,
        bool isNegative = false)
        where T : struct
    {
        if (context.NumberFormat == VariableNumberFormat.Hex)
            return FormatHex(variable, context.CultureInfo);

        if (context.NumberFormat == VariableNumberFormat.Binary)
        {
            Span<long> tmp = stackalloc long[1];
            Span<T> tmpTarget = MemoryMarshal.Cast<long, T>(tmp);

            tmp[0] = 0;
            tmpTarget[0] = variable;

            if (singedBinaryPad > -1 && (isNegative || context.Options.PadUnsignedBinaryNumbers))
            {
                if (isNegative)
                {
                    var varU = unchecked((ulong)tmp[0]);
                    varU = ~varU;
                    varU += 1;
                    var varS = unchecked((long)varU);

                    return "-" + Convert.ToString(varS, 2).PadLeft(singedBinaryPad, '0');
                }
                else
                {
                    return Convert.ToString(tmp[0], 2).PadLeft(singedBinaryPad, '0');
                }
            }

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

    /// <summary>
    /// Formats an address (as a hexadecimal number prefixed with 0x).
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static string FormatAddress(uint address)
    {
        return $"0x{address:x}";
    }

    /// <summary>
    /// Parses an address (a hexadecimal number, possibly prefixed with 0x)
    /// </summary>
    public static bool TryParseAddress(string value, out uint address)
    {
        return value.StartsWith("0x")
            ? uint.TryParse(value.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out address)
            : uint.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out address);
    }

    /// <summary>
    /// Parses a 32bit number and returns its bit value as an unsigned int.
    /// The number may be hexadecimal (starts with 0x or ends with x/h) or binary (starts with 0b or ends with b).
    /// The method tries to parse the input first as an uint, then as an int and then as a float.
    /// Non-uint numbers are reinterpreted as uint but their bit value stays the same.
    /// If all this fails, it tries again using the invariant culture.
    /// </summary>
    /// <param name="value">The input value.</param>
    /// <param name="formatProvider">An object that supplies culture-specific formatting information about the input.</param>
    /// <returns>The parsed integer.</returns>
    /// <exception cref="InvalidVariableFormatException">The input doesn't contain any recognizable 32b number.</exception>
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

    /// <summary>
    /// Parses a 32b float. If it fails, tries again using the invariant culture.
    /// </summary>
    /// <param name="value">The input value.</param>
    /// <param name="formatProvider">An object that supplies culture-specific formatting information about the input.</param>
    /// <returns>The parsed float.</returns>
    /// <exception cref="InvalidVariableFormatException">The input doesn't contain a float.</exception>
    public static uint ParseNumber32F(string value, IFormatProvider? formatProvider)
    {
        if (float.TryParse(value, NumberStyles.Float, formatProvider, out var f))
            return Unsafe.As<float, uint>(ref f);

        if (!Equals(formatProvider, CultureInfo.InvariantCulture))
            return ParseNumber32F(value, CultureInfo.InvariantCulture);

        throw new InvalidVariableFormatException(ExceptionMessages.InvalidVariableFormat32Float);
    }

    /// <summary>
    /// Checks if the input is prefixed with 0b or suffixed with b and not prefixed with 0x. 
    /// </summary>
    /// <returns></returns>
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

    /// <summary>
    /// Parses a 64bit number and returns its bit value as an unsigned int.
    /// The number may be hexadecimal (starts with 0x or ends with x/h) or binary (starts with 0b or ends with b).
    /// The method tries to parse the input first as an uint, then as an int and then as a double (64b float).
    /// Non-uint numbers are reinterpreted as uint but their bit value stays the same.
    /// If all this fails, it tries again using the invariant culture.
    /// </summary>
    /// <param name="value">The input value.</param>
    /// <param name="formatProvider">An object that supplies culture-specific formatting information about the input.</param>
    /// <returns>The parsed integer.</returns>
    /// <exception cref="InvalidVariableFormatException">The input doesn't contain any recognizable 64b number.</exception>
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

    /// <summary>
    /// Parses a 64b float (double). If it fails, tries again using the invariant culture.
    /// </summary>
    /// <param name="value">The input value.</param>
    /// <param name="formatProvider">An object that supplies culture-specific formatting information about the input.</param>
    /// <returns>The parsed float.</returns>
    /// <exception cref="InvalidVariableFormatException">The input doesn't contain a double.</exception>
    public static ulong ParseNumber64F(string value, IFormatProvider? formatProvider)
    {
        if (double.TryParse(value, NumberStyles.Float, formatProvider, out var d))
            return Unsafe.As<double, uint>(ref d);

        if (!Equals(formatProvider, CultureInfo.InvariantCulture))
            return ParseNumber64F(value, CultureInfo.InvariantCulture);

        throw new InvalidVariableFormatException(ExceptionMessages.InvalidVariableFormat64Float);
    }

    /// <summary>
    /// If <typeparamref name="T"/> is a signed numeral type, formats the input number as a signed hex, prefixed with 0x.
    /// Otherwise formats the number as a hex in the normal way and prefixes it with 0x.
    /// </summary>
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

    /// <summary>
    /// Parses a 32b binary number.
    /// </summary>
    /// <exception cref="InvalidVariableFormatException">Invalid character.</exception>
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

    /// <summary>
    /// Parses a 64b binary number.
    /// </summary>
    /// <exception cref="InvalidVariableFormatException">Invalid character.</exception>
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
