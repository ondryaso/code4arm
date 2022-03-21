// TokenAnalyser.cs
// Author: Ondřej Ondryáš

using System.Text.RegularExpressions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Extensions;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.CodeAnalysis;

public static class TokenAnalyser
{
    public static AnalysedOperandToken CheckToken(OperandDescriptor descriptor, Match operandMatch,
        List<AnalysedOperandToken> previousTokens, OperandToken token, Range tokenRange, Group tokenMatch)
    {
        if (token.Type == OperandTokenType.ImmediateConstant)
        {
            return CheckImmediateConstant(token, tokenRange, tokenMatch);
        }

        if (token.Type == OperandTokenType.Immediate)
        {
            return CheckBasicImmediate(token, tokenRange, tokenMatch);
        }

        if (token.Type == OperandTokenType.ImmediateShift)
        {
            foreach (var previousToken in previousTokens)
            {
                if (previousToken.Type == OperandTokenType.ShiftType)
                {
                    return CheckImmediateShift(token, tokenRange, tokenMatch, previousToken.Data.ShiftType);
                }
            }

            throw new Exception("Unexpected immediate shift token defined.");
        }

        if (token.Type == OperandTokenType.Register)
        {
            return CheckRegister(descriptor, token, tokenRange, tokenMatch);
        }

        if (token.Type == OperandTokenType.SimdRegister)
        {
            // TODO: SIMD registers checking
        }

        if (token.Type == OperandTokenType.ShiftType)
        {
            return CheckShiftType(token, tokenRange, tokenMatch);
        }

        return new AnalysedOperandToken(token.Type, OperandTokenResult.Valid, tokenRange, tokenMatch.Value);
    }

    public static AnalysedOperandToken CheckImmediateConstant(OperandToken token, Range tokenRange, Group tokenMatch)
    {
        var numberParsed = int.Parse(tokenMatch.Value);
        var negative = numberParsed < 0;
        var number = negative ? -numberParsed : numberParsed;

        var valid = CheckModifiedImmediateConstant((uint)number);
        if (!valid)
        {
            return new AnalysedOperandToken(token.Type, OperandTokenResult.InvalidImmediateConstantValue,
                tokenRange, tokenMatch.Value, false, numberParsed);
        }

        if (negative)
        {
            return new AnalysedOperandToken(token.Type, OperandTokenResult.ImmediateConstantNegative, tokenRange,
                tokenMatch.Value, true, numberParsed);
        }

        return new AnalysedOperandToken(token.Type, OperandTokenResult.Valid, tokenRange, tokenMatch.Value,
            false, numberParsed);
    }

    public static AnalysedOperandToken CheckBasicImmediate(OperandToken token, Range tokenRange, Group tokenMatch)
    {
        if (string.IsNullOrWhiteSpace(tokenMatch.Value))
        {
            // TODO: this is probably right and absence of the token should be questioned
            // on a higher level but think about it
            return new AnalysedOperandToken(token.Type, OperandTokenResult.Valid, tokenRange, tokenMatch.Value, false,
                0);
        }
        
        var numberParsed = int.Parse(tokenMatch.Value);
        var number = (uint)(numberParsed > 0 ? numberParsed : -numberParsed);
        var maxValue = (1u << token.ImmediateSize) - 1;

        if (token.IsImmediateDiv4)
        {
            maxValue *= 4;
        }

        if (number > maxValue || (token.IsImmediateDiv4 && number % 4 != 0))
        {
            return new AnalysedOperandToken(token.Type, OperandTokenResult.InvalidImmediateValue,
                tokenRange, tokenMatch.Value, false, numberParsed);
        }

        return new AnalysedOperandToken(token.Type, OperandTokenResult.Valid, tokenRange, tokenMatch.Value, false,
            numberParsed);
    }

    public static AnalysedOperandToken CheckImmediateShift(OperandToken token, Range tokenRange, Group tokenMatch,
        ShiftType shiftType)
    {
        var number = int.Parse(tokenMatch.Value);

        var valid = shiftType switch
        {
            ShiftType.LSL or ShiftType.ROR => number is >= 1 and <= 31,
            ShiftType.LSR or ShiftType.ASR => number is >= 1 and <= 32,
            _ => false
        };

        return new AnalysedOperandToken(token.Type,
            valid ? OperandTokenResult.Valid : OperandTokenResult.InvalidImmediateValue,
            tokenRange, tokenMatch.Value, false, number);
    }

    public static AnalysedOperandToken CheckRegister(OperandDescriptor descriptor,
        OperandToken token, Range tokenRange, Group tokenMatch)
    {
        if (!RegisterExtensions.TryParseRegister(tokenMatch.Value, out var register))
        {
            throw new Exception("Unexpected register name.");
        }

        if (!token.RegisterMask.HasFlag(register))
        {
            if (descriptor.Type == OperandType.Register)
            {
                return new AnalysedOperandToken(token.Type, OperandTokenResult.InvalidRegister, tokenRange,
                    tokenMatch.Value, false, register);
            }

            if (descriptor.Type == OperandType.RegisterList)
            {
                return new AnalysedOperandToken(token.Type,
                    register == Register.PC
                        ? OperandTokenResult.RegisterListCannotContainPc
                        : OperandTokenResult.InvalidRegisterListEntry, tokenRange, tokenMatch.Value,
                    false, register);
            }
        }

        return new AnalysedOperandToken(token.Type, OperandTokenResult.Valid, tokenRange, tokenMatch.Value, false,
            register);
    }

    public static AnalysedOperandToken CheckShiftType(OperandToken token, Range tokenRange, Group tokenMatch)
    {
        if (!EnumExtensions.TryParseName(tokenMatch.Value, out ShiftType shiftType))
        {
            return new AnalysedOperandToken(token.Type, OperandTokenResult.InvalidShiftType, tokenRange,
                tokenMatch.Value);
        }

        if (token.AllowedShiftTypes != null)
        {
            if (!token.AllowedShiftTypes.Contains(shiftType))
            {
                return new AnalysedOperandToken(token.Type, OperandTokenResult.InvalidShiftType, tokenRange,
                    tokenMatch.Value, false, shiftType);
            }
        }

        return new AnalysedOperandToken(token.Type, OperandTokenResult.Valid, tokenRange,
            tokenMatch.Value, false, shiftType);
    }

    /// <summary>
    /// Checks whether the specified number is a valid modified immediate constant.
    /// </summary>
    /// <remarks>See the Architecture Reference Manual, chapter F1.7.7.</remarks>
    /// <returns></returns>
    public static bool CheckModifiedImmediateConstant(uint number)
    {
        if (number <= 0xFFu) return true;
        for (var i = 2; i < 32; i += 2)
        {
            // Rotate number (left) and check if it's under 255
            if (((number << i) | (number >> (32 - i))) <= 0xFFu)
            {
                return true;
            }
        }

        return false;
    }
}
