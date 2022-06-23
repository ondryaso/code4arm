// Tools.cs
// Original source: https://www.codeproject.com/Articles/19274/A-printf-implementation-in-C
// Author: Richard Prinz
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) 2019 Richard Prinz, 2022 Ondřej Ondryáš.

#nullable disable

#region Usings

using System.Text;
using System.Text.RegularExpressions;
using Code4Arm.ExecutionCore.Environment;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Extensions;

#endregion

// ReSharper disable once CheckNamespace
namespace AT.MIN
{
    public static class Tools
    {
        #region Public Methods

        #region IsNumericType

        /// <summary>
        /// Determines whether the specified value is of numeric type.
        /// </summary>
        /// <param name="o">The object to check.</param>
        /// <returns>
        /// 	<c>true</c> if o is a numeric type; otherwise, <c>false</c>.
        /// </returns>
        public static bool IsNumericType(object o)
        {
            return (o is byte ||
                o is sbyte ||
                o is short ||
                o is ushort ||
                o is int ||
                o is uint ||
                o is long ||
                o is ulong ||
                o is float ||
                o is double ||
                o is decimal);
        }

        #endregion

        #region IsPositive

        /// <summary>
        /// Determines whether the specified value is positive.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <param name="zeroIsPositive">if set to <c>true</c> treats 0 as positive.</param>
        /// <returns>
        /// 	<c>true</c> if the specified value is positive; otherwise, <c>false</c>.
        /// </returns>
        public static bool IsPositive(object value, bool zeroIsPositive)
        {
            switch (Type.GetTypeCode(value.GetType()))
            {
                case TypeCode.SByte:
                    return (zeroIsPositive ? (sbyte)value >= 0 : (sbyte)value > 0);
                case TypeCode.Int16:
                    return (zeroIsPositive ? (short)value >= 0 : (short)value > 0);
                case TypeCode.Int32:
                    return (zeroIsPositive ? (int)value >= 0 : (int)value > 0);
                case TypeCode.Int64:
                    return (zeroIsPositive ? (long)value >= 0 : (long)value > 0);
                case TypeCode.Single:
                    return (zeroIsPositive ? (float)value >= 0 : (float)value > 0);
                case TypeCode.Double:
                    return (zeroIsPositive ? (double)value >= 0 : (double)value > 0);
                case TypeCode.Decimal:
                    return (zeroIsPositive ? (decimal)value >= 0 : (decimal)value > 0);
                case TypeCode.Byte:
                    return (zeroIsPositive || (byte)value > 0);
                case TypeCode.UInt16:
                    return (zeroIsPositive || (ushort)value > 0);
                case TypeCode.UInt32:
                    return (zeroIsPositive || (uint)value > 0);
                case TypeCode.UInt64:
                    return (zeroIsPositive || (ulong)value > 0);
                case TypeCode.Char:
                    return (zeroIsPositive || (char)value != '\0');
                default:
                    return false;
            }
        }

        #endregion

        #region ToUnsigned

        /// <summary>
        /// Converts the specified values boxed type to its correpsonding unsigned
        /// type.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns>A boxed numeric object whos type is unsigned.</returns>
        public static object ToUnsigned(object value)
        {
            switch (Type.GetTypeCode(value.GetType()))
            {
                case TypeCode.SByte:
                    return (byte)((sbyte)value);
                case TypeCode.Int16:
                    return (ushort)((short)value);
                case TypeCode.Int32:
                    return (uint)((int)value);
                case TypeCode.Int64:
                    return (ulong)((long)value);

                case TypeCode.Byte:
                    return value;
                case TypeCode.UInt16:
                    return value;
                case TypeCode.UInt32:
                    return value;
                case TypeCode.UInt64:
                    return value;

                case TypeCode.Single:
                    return (UInt32)((float)value);
                case TypeCode.Double:
                    return (ulong)((double)value);
                case TypeCode.Decimal:
                    return (ulong)((decimal)value);

                default:
                    return null;
            }
        }

        #endregion

        #region ToInteger

        /// <summary>
        /// Converts the specified values boxed type to its correpsonding integer
        /// type.
        /// </summary>
        /// <param name="value">The value.</param>
        /// <returns>A boxed numeric object whos type is an integer type.</returns>
        public static object ToInteger(object value, bool round)
        {
            switch (Type.GetTypeCode(value.GetType()))
            {
                case TypeCode.SByte:
                    return value;
                case TypeCode.Int16:
                    return value;
                case TypeCode.Int32:
                    return value;
                case TypeCode.Int64:
                    return value;

                case TypeCode.Byte:
                    return value;
                case TypeCode.UInt16:
                    return value;
                case TypeCode.UInt32:
                    return value;
                case TypeCode.UInt64:
                    return value;

                case TypeCode.Single:
                    return (round ? (int)Math.Round((float)value) : (int)((float)value));
                case TypeCode.Double:
                    return (round ? (long)Math.Round((double)value) : (long)((double)value));
                case TypeCode.Decimal:
                    return (round ? Math.Round((decimal)value) : (decimal)value);

                default:
                    return null;
            }
        }

        #endregion

        #region UnboxToLong

        public static long UnboxToLong(object value, bool round)
        {
            switch (Type.GetTypeCode(value.GetType()))
            {
                case TypeCode.SByte:
                    return (long)((sbyte)value);
                case TypeCode.Int16:
                    return (long)((short)value);
                case TypeCode.Int32:
                    return (long)((int)value);
                case TypeCode.Int64:
                    return (long)value;

                case TypeCode.Byte:
                    return (long)((byte)value);
                case TypeCode.UInt16:
                    return (long)((ushort)value);
                case TypeCode.UInt32:
                    return (long)((uint)value);
                case TypeCode.UInt64:
                    return (long)((ulong)value);

                case TypeCode.Single:
                    return (round ? (long)Math.Round((float)value) : (long)((float)value));
                case TypeCode.Double:
                    return (round ? (long)Math.Round((double)value) : (long)((double)value));
                case TypeCode.Decimal:
                    return (round ? (long)Math.Round((decimal)value) : (long)((decimal)value));

                default:
                    return 0;
            }
        }

        #endregion

        #region ReplaceMetaChars

        /// <summary>
        /// Replaces the string representations of meta chars with their corresponding
        /// character values.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <returns>A string with all string meta chars are replaced</returns>
        public static string ReplaceMetaChars(string input)
        {
            return Regex.Replace(input, @"(\\)(\d{3}|[^\d])?", new MatchEvaluator(ReplaceMetaCharsMatch));
        }

        private static string ReplaceMetaCharsMatch(Match m)
        {
            // convert octal quotes (like \040)
            if (m.Groups[2].Length == 3)
                return Convert.ToChar(Convert.ToByte(m.Groups[2].Value, 8)).ToString();
            else
            {
                // convert all other special meta characters
                //TODO: \xhhh hex and possible dec !!
                switch (m.Groups[2].Value)
                {
                    case "0": // null
                        return "\0";
                    case "a": // alert (beep)
                        return "\a";
                    case "b": // BS
                        return "\b";
                    case "f": // FF
                        return "\f";
                    case "v": // vertical tab
                        return "\v";
                    case "r": // CR
                        return "\r";
                    case "n": // LF
                        return "\n";
                    case "t": // Tab
                        return "\t";
                    default:
                        // if neither an octal quote nor a special meta character
                        // so just remove the backslash
                        return m.Groups[2].Value;
                }
            }
        }

        #endregion

        public static string PrintF(string format, IUnicorn unicorn, StringBuilder stringBuilder = null)
        {
            #region Variables

            var f = stringBuilder ?? new StringBuilder();
            var r = new Regex(@"\%(\d*\$)?([\'\#\-\+ ]*)(\d*)(?:\.(\d+))?([hl])?([dioxXucsfeEgGpn%])");
            //"%[parameter][flags][width][.precision][length]type"

            Match m;
            string w;
            var defaultParamIx = 0;
            object o;

            var flagLeft2Right = false;
            var flagAlternate = false;
            var flagPositiveSign = false;
            var flagPositiveSpace = false;
            var flagZeroPadding = false;
            var flagGroupThousands = false;

            var fieldLength = 0;
            var fieldPrecision = 0;
            var shortLongIndicator = '\0';
            var formatSpecifier = '\0';
            var paddingCharacter = ' ';

            #endregion
            
            // PART 1: DETERMINE PARAMETERS
            var paramTypes = new List<AbiType>() { AbiTypes.DataPointer };
            m = r.Match(format);
            while (m.Success)
            {
                // extract short / long indicator
                shortLongIndicator = Char.MinValue;
                if (m.Groups[5] != null && m.Groups[5].Value.Length > 0)
                    shortLongIndicator = m.Groups[5].Value[0];

                // extract format
                formatSpecifier = Char.MinValue;
                if (m.Groups[6] != null && m.Groups[6].Value.Length > 0)
                    formatSpecifier = m.Groups[6].Value[0];

                // convert value parameters to a string depending on the formatSpecifier
                switch (formatSpecifier)
                {
                    case 'd': // integer
                    case 'i':
                        if (shortLongIndicator == 'h')
                            paramTypes.Add(AbiTypes.SignedHalfWord);
                        else if (shortLongIndicator == 'l')
                            paramTypes.Add(AbiTypes.SignedDoubleWord);
                        else
                            paramTypes.Add(AbiTypes.SignedWord);

                        break;
                    case 'o': // unsigned integer
                    case 'x':
                    case 'X':
                    case 'u':
                        if (shortLongIndicator == 'h')
                            paramTypes.Add(AbiTypes.UnsignedHalfWord);
                        else if (shortLongIndicator == 'l')
                            paramTypes.Add(AbiTypes.UnsignedDoubleWord);
                        else
                            paramTypes.Add(AbiTypes.UnsignedWord);

                        break;
                    case 'c': // character
                        paramTypes.Add(AbiTypes.SignedByte);

                        break;
                    case 's': // string
                        paramTypes.Add(AbiTypes.DataPointer);

                        break;
                    case 'f': // double
                    case 'e':
                    case 'E':
                    case 'g':
                    case 'G':
                    case 'a':
                    case 'A':
                        paramTypes.Add(AbiTypes.DoublePrecision);

                        break;
                    case 'p': // pointer
                        paramTypes.Add(AbiTypes.DataPointer);

                        break;
                    case 'n': // number of characters so far
                        throw new NotImplementedException();
                }

                m = r.Match(format, m.Index + m.Length);
            }

            // PART 2: MAKE STRING
            var paramsAdjusted = AbiUtils.AdjustParameterTypes(paramTypes);
            var targetSize = AbiUtils.GetParametersSize(paramsAdjusted);
            Span<byte> target = stackalloc byte[targetSize];
            AbiUtils.GetParameters(unicorn, target, false, paramsAdjusted);

            f.Append(format);
            m = r.Match(format);
            while (m.Success)
            {
                #region parameter index

                var paramIx = defaultParamIx;
                if (m.Groups[1] != null && m.Groups[1].Value.Length > 0)
                {
                    var val = m.Groups[1].Value.Substring(0, m.Groups[1].Value.Length - 1);
                    paramIx = Convert.ToInt32(val) - 1;
                }

                #endregion

                #region format flags

                // extract format flags
                flagAlternate = false;
                flagLeft2Right = false;
                flagPositiveSign = false;
                flagPositiveSpace = false;
                flagZeroPadding = false;
                flagGroupThousands = false;
                if (m.Groups[2] != null && m.Groups[2].Value.Length > 0)
                {
                    var flags = m.Groups[2].Value;

                    flagAlternate = (flags.IndexOf('#') >= 0);
                    flagLeft2Right = (flags.IndexOf('-') >= 0);
                    flagPositiveSign = (flags.IndexOf('+') >= 0);
                    flagPositiveSpace = (flags.IndexOf(' ') >= 0);
                    flagGroupThousands = (flags.IndexOf('\'') >= 0);

                    // positive + indicator overrides a
                    // positive space character
                    if (flagPositiveSign && flagPositiveSpace)
                        flagPositiveSpace = false;
                }

                #endregion

                #region field length

                // extract field length and 
                // pading character
                paddingCharacter = ' ';
                fieldLength = int.MinValue;
                if (m.Groups[3] != null && m.Groups[3].Value.Length > 0)
                {
                    fieldLength = Convert.ToInt32(m.Groups[3].Value);
                    flagZeroPadding = (m.Groups[3].Value[0] == '0');
                }

                #endregion

                if (flagZeroPadding)
                    paddingCharacter = '0';

                // left2right allignment overrides zero padding
                if (flagLeft2Right && flagZeroPadding)
                {
                    flagZeroPadding = false;
                    paddingCharacter = ' ';
                }

                #region field precision

                // extract field precision
                fieldPrecision = int.MinValue;
                if (m.Groups[4] != null && m.Groups[4].Value.Length > 0)
                    fieldPrecision = Convert.ToInt32(m.Groups[4].Value);

                #endregion

                #region short / long indicator

                // extract short / long indicator
                shortLongIndicator = Char.MinValue;
                if (m.Groups[5] != null && m.Groups[5].Value.Length > 0)
                    shortLongIndicator = m.Groups[5].Value[0];

                #endregion

                #region format specifier

                // extract format
                formatSpecifier = Char.MinValue;
                if (m.Groups[6] != null && m.Groups[6].Value.Length > 0)
                    formatSpecifier = m.Groups[6].Value[0];

                #endregion

                // default precision is 6 digits if none is specified except
                if (fieldPrecision == int.MinValue &&
                    formatSpecifier != 's' &&
                    formatSpecifier != 'c' &&
                    Char.ToUpper(formatSpecifier) != 'X' &&
                    formatSpecifier != 'o')
                    fieldPrecision = 6;

                #region get next value parameter

                var abiParam = paramsAdjusted[paramIx + 1]; // +1 because the first one is the format string ptr
                if (abiParam.Size == 4 && abiParam.Class is AbiTypeClass.Integral or AbiTypeClass.Pointer)
                {
                    o = abiParam.MachineType.IsSigned()
                        ? AbiUtils.GetParameter<int>(target, paramIx + 1, paramsAdjusted)
                        : AbiUtils.GetParameter<uint>(target, paramIx + 1, paramsAdjusted);
                }
                else if (abiParam.Size == 8)
                {
                    if (abiParam.Class == AbiTypeClass.Integral)
                        o = abiParam.MachineType.IsSigned()
                            ? AbiUtils.GetParameter<long>(target, paramIx + 1, paramsAdjusted)
                            : AbiUtils.GetParameter<ulong>(target, paramIx + 1, paramsAdjusted);
                    else
                        o = AbiUtils.GetParameter<double>(target, paramIx + 1, paramsAdjusted);
                }
                else
                {
                    o = "INVALID VALUE";
                }

                if (shortLongIndicator == 'h')
                {
                    if (o is int)
                        o = (short)((int)o);
                    else if (o is long)
                        o = (short)((long)o);
                    else if (o is uint)
                        o = (ushort)((uint)o);
                    else if (o is ulong)
                        o = (ushort)((ulong)o);
                }
                else if (shortLongIndicator == 'l')
                {
                    /*if (o is short)
                        o = (long)((short)o);
                    else */
                    if (o is int)
                        o = (long)((int)o);
                    /*else if (o is ushort)
                        o = (ulong)((ushort)o);*/
                    else if (o is uint)
                        o = (ulong)((uint)o);
                }

                #endregion

                // convert value parameters to a string depending on the formatSpecifier
                w = String.Empty;
                switch (formatSpecifier)
                {
                    #region % - character

                    case '%': // % character
                        w = "%";

                        break;

                    #endregion

                    #region d - integer

                    case 'd': // integer
                        w = FormatNumber((flagGroupThousands ? "n" : "d"), flagAlternate,
                            fieldLength, int.MinValue, flagLeft2Right,
                            flagPositiveSign, flagPositiveSpace,
                            paddingCharacter, o);
                        defaultParamIx++;

                        break;

                    #endregion

                    #region i - integer

                    case 'i': // integer
                        goto case 'd';

                    #endregion

                    #region o - octal integer

                    case 'o': // octal integer - no leading zero
                        w = FormatOct("o", flagAlternate,
                            fieldLength, int.MinValue, flagLeft2Right,
                            paddingCharacter, o);
                        defaultParamIx++;

                        break;

                    #endregion

                    #region x - hex integer

                    case 'x': // hex integer - no leading zero
                        w = FormatHex("x", flagAlternate,
                            fieldLength, fieldPrecision, flagLeft2Right,
                            paddingCharacter, o);
                        defaultParamIx++;

                        break;

                    #endregion

                    #region X - hex integer

                    case 'X': // same as x but with capital hex characters
                        w = FormatHex("X", flagAlternate,
                            fieldLength, fieldPrecision, flagLeft2Right,
                            paddingCharacter, o);
                        defaultParamIx++;

                        break;

                    #endregion

                    #region u - unsigned integer

                    case 'u': // unsigned integer
                        w = FormatNumber((flagGroupThousands ? "n" : "d"), flagAlternate,
                            fieldLength, int.MinValue, flagLeft2Right,
                            false, false,
                            paddingCharacter, ToUnsigned(o));
                        defaultParamIx++;

                        break;

                    #endregion

                    #region c - character

                    case 'c': // character
                        if (IsNumericType(o))
                            w = Convert.ToChar(o).ToString();
                        else if (o is char)
                            w = ((char)o).ToString();
                        else if (o is string && ((string)o).Length > 0)
                            w = ((string)o)[0].ToString();
                        defaultParamIx++;

                        break;

                    #endregion

                    #region s - string

                    case 's': // string
                        var t = "{0" + (fieldLength != int.MinValue
                            ? "," + (flagLeft2Right ? "-" : String.Empty) + fieldLength.ToString()
                            : String.Empty) + ":s}";
                        w = unicorn.MemReadCString((uint)o);
                        if (fieldPrecision >= 0)
                            w = w.Substring(0, fieldPrecision);

                        if (fieldLength != int.MinValue)
                            if (flagLeft2Right)
                                w = w.PadRight(fieldLength, paddingCharacter);
                            else
                                w = w.PadLeft(fieldLength, paddingCharacter);
                        defaultParamIx++;

                        break;

                    #endregion

                    #region f - double number

                    case 'f': // double
                        w = FormatNumber((flagGroupThousands ? "n" : "f"), flagAlternate,
                            fieldLength, fieldPrecision, flagLeft2Right,
                            flagPositiveSign, flagPositiveSpace,
                            paddingCharacter, o);
                        defaultParamIx++;

                        break;

                    #endregion

                    #region e - exponent number

                    case 'e': // double / exponent
                        w = FormatNumber("e", flagAlternate,
                            fieldLength, fieldPrecision, flagLeft2Right,
                            flagPositiveSign, flagPositiveSpace,
                            paddingCharacter, o);
                        defaultParamIx++;

                        break;

                    #endregion

                    #region E - exponent number

                    case 'E': // double / exponent
                        w = FormatNumber("E", flagAlternate,
                            fieldLength, fieldPrecision, flagLeft2Right,
                            flagPositiveSign, flagPositiveSpace,
                            paddingCharacter, o);
                        defaultParamIx++;

                        break;

                    #endregion

                    #region g - general number

                    case 'g': // double / exponent
                        w = FormatNumber("g", flagAlternate,
                            fieldLength, fieldPrecision, flagLeft2Right,
                            flagPositiveSign, flagPositiveSpace,
                            paddingCharacter, o);
                        defaultParamIx++;

                        break;

                    #endregion

                    #region G - general number

                    case 'G': // double / exponent
                        w = FormatNumber("G", flagAlternate,
                            fieldLength, fieldPrecision, flagLeft2Right,
                            flagPositiveSign, flagPositiveSpace,
                            paddingCharacter, o);
                        defaultParamIx++;

                        break;

                    #endregion

                    #region p - pointer

                    case 'p': // pointer
                        if (o is IntPtr)
                            w = "0x" + ((IntPtr)o).ToString("x");
                        defaultParamIx++;

                        break;

                    #endregion

                    #region n - number of processed chars so far

                    case 'n': // number of characters so far
                        w = FormatNumber("d", flagAlternate,
                            fieldLength, int.MinValue, flagLeft2Right,
                            flagPositiveSign, flagPositiveSpace,
                            paddingCharacter, m.Index);

                        break;

                    #endregion

                    default:
                        w = String.Empty;
                        defaultParamIx++;

                        break;
                }

                // replace format parameter with parameter value
                // and start searching for the next format parameter
                // AFTER the position of the current inserted value
                // to prohibit recursive matches if the value also
                // includes a format specifier
                f.Remove(m.Index, m.Length);
                f.Insert(m.Index, w);
                m = r.Match(f.ToString(), m.Index + w.Length);
            }

            return f.ToString();
        }

        #endregion


        #region Private Methods

        #region FormatOCT

        private static string FormatOct(string nativeFormat, bool alternate,
            int fieldLength, int fieldPrecision,
            bool left2Right,
            char padding, object value)
        {
            var w = String.Empty;
            var lengthFormat = "{0" + (fieldLength != int.MinValue
                ? "," + (left2Right ? "-" : String.Empty) + fieldLength.ToString()
                : String.Empty) + "}";

            if (IsNumericType(value))
            {
                w = Convert.ToString(UnboxToLong(value, true), 8);

                if (left2Right || padding == ' ')
                {
                    if (alternate && w != "0")
                        w = "0" + w;
                    w = String.Format(lengthFormat, w);
                }
                else
                {
                    if (fieldLength != int.MinValue)
                        w = w.PadLeft(fieldLength - (alternate && w != "0" ? 1 : 0), padding);
                    if (alternate && w != "0")
                        w = "0" + w;
                }
            }

            return w;
        }

        #endregion

        #region FormatHEX

        private static string FormatHex(string nativeFormat, bool alternate,
            int fieldLength, int fieldPrecision,
            bool left2Right,
            char padding, object value)
        {
            var w = String.Empty;
            var lengthFormat = "{0" + (fieldLength != int.MinValue
                ? "," + (left2Right ? "-" : String.Empty) + fieldLength.ToString()
                : String.Empty) + "}";
            var numberFormat = "{0:" + nativeFormat +
                (fieldPrecision != int.MinValue ? fieldPrecision.ToString() : String.Empty) + "}";

            if (IsNumericType(value))
            {
                w = String.Format(numberFormat, value);

                if (left2Right || padding == ' ')
                {
                    if (alternate)
                        w = (nativeFormat == "x" ? "0x" : "0X") + w;
                    w = String.Format(lengthFormat, w);
                }
                else
                {
                    if (fieldLength != int.MinValue)
                        w = w.PadLeft(fieldLength - (alternate ? 2 : 0), padding);
                    if (alternate)
                        w = (nativeFormat == "x" ? "0x" : "0X") + w;
                }
            }

            return w;
        }

        #endregion

        #region FormatNumber

        private static string FormatNumber(string nativeFormat, bool alternate,
            int fieldLength, int fieldPrecision,
            bool left2Right,
            bool positiveSign, bool positiveSpace,
            char padding, object value)
        {
            var w = String.Empty;
            var lengthFormat = "{0" + (fieldLength != int.MinValue
                ? "," + (left2Right ? "-" : String.Empty) + fieldLength.ToString()
                : String.Empty) + "}";
            var numberFormat = "{0:" + nativeFormat +
                (fieldPrecision != int.MinValue ? fieldPrecision.ToString() : "0") + "}";

            if (IsNumericType(value))
            {
                w = String.Format(numberFormat, value);

                if (left2Right || padding == ' ')
                {
                    if (IsPositive(value, true))
                        w = (positiveSign ? "+" : (positiveSpace ? " " : String.Empty)) + w;
                    w = String.Format(lengthFormat, w);
                }
                else
                {
                    if (w.StartsWith("-"))
                        w = w.Substring(1);
                    if (fieldLength != int.MinValue)
                        w = w.PadLeft(fieldLength - 1, padding);
                    if (IsPositive(value, true))
                        w = (positiveSign
                            ? "+"
                            : (positiveSpace
                                ? " "
                                : (fieldLength != int.MinValue ? padding.ToString() : String.Empty))) + w;
                    else
                        w = "-" + w;
                }
            }

            return w;
        }

        #endregion

        #endregion
    }
}

#nullable restore
