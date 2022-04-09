// TokenAnalyser.cs
// Author: Ondřej Ondryáš

using System.Text.RegularExpressions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.CodeAnalysis.Models.Abstractions;
using Armfors.LanguageServer.Extensions;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.CodeAnalysis;

public static class TokenAnalyser
{
    public static AnalysedOperandToken CheckToken(IOperandDescriptor descriptor, Match operandMatch,
        List<AnalysedOperandToken> previousTokens, OperandTokenDescriptor tokenDescriptor, Range tokenRange, Group tokenMatch)
    {
        if (tokenDescriptor.Type == OperandTokenType.ImmediateConstant)
        {
            return CheckImmediateConstant(tokenDescriptor, tokenRange, tokenMatch);
        }

        if (tokenDescriptor.Type == OperandTokenType.Immediate)
        {
            return CheckBasicImmediate(tokenDescriptor, tokenRange, tokenMatch);
        }

        if (tokenDescriptor.Type == OperandTokenType.ImmediateShift)
        {
            foreach (var previousToken in previousTokens)
            {
                if (previousToken.Type == OperandTokenType.ShiftType)
                {
                    return CheckImmediateShift(tokenDescriptor, tokenRange, tokenMatch, previousToken.Data.ShiftType);
                }
            }

            throw new Exception("Unexpected immediate shift token defined.");
        }

        if (tokenDescriptor.Type == OperandTokenType.Register)
        {
            return CheckRegister(descriptor, tokenDescriptor, tokenRange, tokenMatch);
        }

        if (tokenDescriptor.Type == OperandTokenType.SimdRegister)
        {
            // TODO: SIMD registers checking
        }

        if (tokenDescriptor.Type == OperandTokenType.ShiftType)
        {
            return CheckShiftType(tokenDescriptor, tokenRange, tokenMatch);
        }

        return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.Valid, tokenRange, tokenMatch.Value);
    }

    public static AnalysedOperandToken CheckImmediateConstant(OperandTokenDescriptor tokenDescriptor, Range tokenRange, Group tokenMatch)
    {
        var numberParsed = int.Parse(tokenMatch.Value);
        var negative = numberParsed < 0;
        var number = negative ? -numberParsed : numberParsed;

        var valid = CheckModifiedImmediateConstant((uint) number);
        if (!valid)
        {
            return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.InvalidImmediateConstantValue,
                tokenRange, tokenMatch.Value, numberParsed);
        }

        if (negative)
        {
            return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.ImmediateConstantNegative, tokenRange,
                tokenMatch.Value, numberParsed, DiagnosticSeverity.Warning);
        }

        return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.Valid, tokenRange, tokenMatch.Value,
            Data: numberParsed);
    }

    public static AnalysedOperandToken CheckBasicImmediate(OperandTokenDescriptor tokenDescriptor, Range tokenRange, Group tokenMatch)
    {
        if (string.IsNullOrWhiteSpace(tokenMatch.Value))
        {
            // TODO: this is probably right and absence of the token should be questioned
            // on a higher level but think about it
            return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.Valid, tokenRange, tokenMatch.Value, 0);
        }

        var numberParsed = int.Parse(tokenMatch.Value);
        var number = (uint) (numberParsed > 0 ? numberParsed : -numberParsed);
        var maxValue = (1u << tokenDescriptor.ImmediateSize) - 1;

        if (tokenDescriptor.IsImmediateDiv4)
        {
            maxValue *= 4;
        }

        if (number > maxValue || (tokenDescriptor.IsImmediateDiv4 && number % 4 != 0))
        {
            return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.InvalidImmediateValue,
                tokenRange, tokenMatch.Value, Data: numberParsed);
        }

        return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.Valid, tokenRange, tokenMatch.Value, numberParsed);
    }

    public static AnalysedOperandToken CheckImmediateShift(OperandTokenDescriptor tokenDescriptor, Range tokenRange, Group tokenMatch,
        ShiftType shiftType)
    {
        if (string.IsNullOrEmpty(tokenMatch.Value))
            return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.SyntaxError, tokenRange, tokenMatch.Value);
        
        var number = int.Parse(tokenMatch.Value);

        var valid = shiftType switch
        {
            ShiftType.LSL or ShiftType.ROR => number is >= 1 and <= 31,
            ShiftType.LSR or ShiftType.ASR => number is >= 1 and <= 32,
            _ => false
        };

        return new AnalysedOperandToken(tokenDescriptor,
            valid ? OperandTokenResult.Valid : OperandTokenResult.InvalidImmediateValue,
            tokenRange, tokenMatch.Value, number);
    }

    public static AnalysedOperandToken CheckRegister(IOperandDescriptor descriptor,
        OperandTokenDescriptor tokenDescriptor, Range tokenRange, Group tokenMatch)
    {
        if (!RegisterExtensions.TryParseRegister(tokenMatch.Value, out var register))
        {
            throw new Exception("Unexpected register name.");
        }

        if (!tokenDescriptor.RegisterMask.HasFlag(register))
        {
            if (descriptor.Type == OperandType.RegisterList)
            {
                return new AnalysedOperandToken(tokenDescriptor,
                    register == Register.PC
                        ? OperandTokenResult.RegisterListCannotContainPc
                        : OperandTokenResult.InvalidRegisterListEntry, tokenRange, tokenMatch.Value,
                    register);
            }
            
            return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.InvalidRegister, tokenRange,
                tokenMatch.Value, register);
        }

        return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.Valid, tokenRange, tokenMatch.Value, register);
    }

    public static AnalysedOperandToken CheckShiftType(OperandTokenDescriptor tokenDescriptor, Range tokenRange, Group tokenMatch)
    {
        if (!EnumExtensions.TryParseName(tokenMatch.Value, out ShiftType shiftType))
        {
            return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.InvalidShiftType, tokenRange,
                tokenMatch.Value);
        }

        if (tokenDescriptor.AllowedShiftTypes != null)
        {
            if (!tokenDescriptor.AllowedShiftTypes.Contains(shiftType))
            {
                return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.InvalidShiftType, tokenRange,
                    tokenMatch.Value, shiftType);
            }
        }

        return new AnalysedOperandToken(tokenDescriptor, OperandTokenResult.Valid, tokenRange,
            tokenMatch.Value, shiftType);
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
