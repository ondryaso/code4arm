// BasicOperandAnalyser.cs
// Author: Ondřej Ondryáš

using System.Text.RegularExpressions;
using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;

namespace Armfors.LanguageServer.CodeAnalysis;

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

public class BasicOperandAnalyser : IOperandAnalyser
{
    private readonly OperandDescriptor _descriptor;

    internal BasicOperandAnalyser(OperandDescriptor descriptor)
    {
        _descriptor = descriptor;
    }

    public AnalysedOperand AnalyseOperand(int operandIndex, int operandPartPositionInLine, Match match,
        Range operandLineRange)
    {
        var resultTokens = new List<AnalysedOperandToken>();
        var input = _descriptor.IsSingleToken
            ? Enumerable.Repeat(
                new KeyValuePair<int, OperandToken>(_descriptor.SingleTokenMatchGroup, _descriptor.SingleToken!), 1)
            : _descriptor.MatchGroupsTokenMappings ?? Enumerable.Empty<KeyValuePair<int, OperandToken>>();

        var hasErrors = false;
        foreach (var (groupIndex, token) in input)
        {
            if (match.Groups.Count <= groupIndex)
                continue;

            var matchGroup = match.Groups[groupIndex];
            var tokenRange = new Range(operandLineRange.Start.Line,
                operandPartPositionInLine + matchGroup.Index, operandLineRange.Start.Line,
                operandPartPositionInLine + matchGroup.Index + matchGroup.Length);

            var aot = TokenAnalyser.CheckToken(_descriptor, match, resultTokens, token, tokenRange, matchGroup);
            if (aot.Result != OperandTokenResult.Valid && !aot.WarningOnly)
            {
                hasErrors = true;
            }

            resultTokens.Add(aot);
        }

        return new AnalysedOperand(operandIndex, _descriptor, operandLineRange,
            hasErrors ? OperandResult.InvalidTokens : OperandResult.Valid, null, resultTokens);
    }
}
