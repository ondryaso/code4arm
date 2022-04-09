// BasicOperandAnalyser.cs
// Author: Ondřej Ondryáš

using System.Collections.Immutable;
using System.Text.RegularExpressions;
using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.CodeAnalysis;

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

public class BasicOperandAnalyser : IOperandAnalyser
{
    private readonly BasicOperandDescriptor _descriptor;

    internal BasicOperandAnalyser(BasicOperandDescriptor descriptor)
    {
        _descriptor = descriptor;
    }

    private readonly Regex _commaRegex = new("\\G ?, ?", RegexOptions.Compiled);

    public AnalysedOperand AnalyseOperand(int operandIndex, int operandPartPositionInLine, List<Match> matches,
        Range operandLineRange, string operandLine)
    {
        var resultTokens = new List<AnalysedOperandToken>();
        var hasErrors = false;
        var position = operandLineRange.Start.Character;

        for ( var mi = 0; mi < matches.Count; mi++)
        {
            var match = matches[mi];

            var hasMappings = _descriptor.MatchGroupsTokenMappings.TryGetValue(mi, out var mappings);

            if (!hasMappings || mappings!.IsEmpty)
            {
                // In a 'literal' match without operand token mappings.
                // These must always be successful.

                if (!match.Success)
                {
                    var range = new Range(operandLineRange.Start.Line, position,
                        operandLineRange.Start.Line, operandPartPositionInLine + operandLine.Length - 1);

                    if (resultTokens.Count > 0)
                        resultTokens[^1].Range.End.Character = range.End.Character;

                    return new AnalysedOperand(operandIndex, _descriptor, operandLineRange,
                        OperandResult.SyntaxError, range, resultTokens);
                }

                if (resultTokens.Count > 0)
                {
                    // If there was a result token before, set its range to the position of the matched literal
                    // Completions will be suggested all the way to this literal.
                    resultTokens[^1].Range.End.Character = operandPartPositionInLine + match.Index;
                }

                if (match.Index != 0)
                {
                    position = operandPartPositionInLine + match.Index + match.Length;
                }

                continue;
            }

            if (hasErrors)
                continue;

            foreach (var (groupIndex, token) in mappings)
            {
                if (!match.Success || match.Length == 0 || (match.Length == 1 && match.Value[0] == ' '))
                {
                    var range = new Range(operandLineRange.Start.Line, position,
                        operandLineRange.Start.Line, position + 1);

                    var commaMatch = _commaRegex.Match(operandLine, position - operandPartPositionInLine);
                    if (commaMatch.Success)
                    {
                        range.Start.Character = operandPartPositionInLine + commaMatch.Index + 1;
                        range.End.Character = operandPartPositionInLine + commaMatch.Index + commaMatch.Length;
                    }

                    position = range.End.Character;

                    if (!match.Success)
                    {
                        resultTokens.Add(new AnalysedOperandToken(token, OperandTokenResult.SyntaxError, range,
                            string.Empty));

                        hasErrors = true;
                    }

                    //mi = matches.Count;  // Ends the outer cycle
                    break;
                }

                if (match.Groups.Count <= groupIndex)
                    continue;

                var matchGroup = match.Groups[groupIndex];

                var matchStart = matchGroup.Index < match.Index ? match.Index : matchGroup.Index;
                var matchLen = matchGroup.Index < match.Index ? match.Length : matchGroup.Length;

                var tokenRange = new Range(operandLineRange.Start.Line,
                    operandPartPositionInLine + matchStart, operandLineRange.Start.Line,
                    operandPartPositionInLine + matchStart + matchLen);

                position = tokenRange.End.Character;

                var aot = TokenAnalyser.CheckToken(_descriptor, match, resultTokens, token, tokenRange, matchGroup);
                if (aot.Result != OperandTokenResult.Valid && aot.Severity == DiagnosticSeverity.Error)
                {
                    hasErrors = true;
                }

                resultTokens.Add(aot);
            }
        }

        /*
         TODO:
         - register list checking
         - alignment checking
        */

        if (resultTokens.Count > 0 && resultTokens[^1].Range.End.Character > operandLineRange.End.Character)
            operandLineRange.End.Character = resultTokens[^1].Range.End.Character;
        
        return new AnalysedOperand(operandIndex, _descriptor, operandLineRange,
            hasErrors ? OperandResult.InvalidTokens : OperandResult.Valid, null, resultTokens);
    }
}
