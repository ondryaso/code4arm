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
        /*
         TODO:
         - imm checking (standalone, constants, in addressing...)
         - reg name and type checking
         - shift type checking
         - literal checking? guess not, this is covered by the regex itself? or should it be?
         - register list checking
         - alignment checking
        */

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
                    var shiftType =
                        Enum.Parse<ShiftType>(previousToken.Text); // Safe, the token has been checked before
                    return CheckImmediateShift(token, tokenRange, tokenMatch, shiftType);
                }
            }

            throw new Exception("Unexpected immediate shift token defined.");
        }

        return new AnalysedOperandToken(token.Type, OperandTokenResult.Valid, tokenRange, tokenMatch.Value);
    }

    public static AnalysedOperandToken CheckImmediateConstant(OperandToken token, Range tokenRange, Group tokenMatch)
    {
        var number = int.Parse(tokenMatch.Value);
        var negative = number < 0;
        if (negative)
        {
            number = -number;
        }

        var valid = CheckModifiedImmediateConstant((uint)number);
        if (!valid)
        {
            return new AnalysedOperandToken(token.Type, OperandTokenResult.InvalidImmediateConstantValue,
                tokenRange, tokenMatch.Value);
        }

        if (negative)
        {
            return new AnalysedOperandToken(token.Type, OperandTokenResult.ImmediateConstantNegative, tokenRange,
                tokenMatch.Value, true);
        }

        return new AnalysedOperandToken(token.Type, OperandTokenResult.Valid, tokenRange, tokenMatch.Value);
    }

    public static AnalysedOperandToken CheckBasicImmediate(OperandToken token, Range tokenRange, Group tokenMatch)
    {
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
                tokenRange, tokenMatch.Value);
        }

        return new AnalysedOperandToken(token.Type, OperandTokenResult.Valid, tokenRange, tokenMatch.Value);
    }

    public static AnalysedOperandToken CheckImmediateShift(OperandToken token, Range tokenRange, Group tokenMatch,
        ShiftType shiftType)
    {
        var number = uint.Parse(tokenMatch.Value);
        var valid = false;

        if (shiftType is ShiftType.LSL or ShiftType.ROR)
        {
            valid = number >= 1 && number <= 31;
        }
        else if (shiftType is ShiftType.LSR or ShiftType.ASR)
        {
            valid = number >= 1 && number <= 32;
        }

        return new AnalysedOperandToken(token.Type,
            valid ? OperandTokenResult.Valid : OperandTokenResult.InvalidImmediateValue,
            tokenRange, tokenMatch.Value);
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
