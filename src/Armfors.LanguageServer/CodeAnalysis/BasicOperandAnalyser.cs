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
    private readonly OperandDescriptor _descriptor;

    internal BasicOperandAnalyser(OperandDescriptor descriptor)
    {
        _descriptor = descriptor;
    }

    public AnalysedOperand AnalyseOperand(int operandIndex, int operandPartPositionInLine, List<Match> matches,
        Range operandLineRange)
    {
        var resultTokens = new List<AnalysedOperandToken>();
        var hasErrors = false;
        Range? lastRange = null;

        for (var mi = 0; mi < matches.Count; mi++)
        {
            ImmutableDictionary<int, OperandToken>? mappings = null;
            var match = matches[mi];

            if (_descriptor.IsSingleToken)
            {
                if (mi != 0)
                    throw new InvalidOperationException();

                mappings = ImmutableDictionary<int, OperandToken>.Empty.Add(_descriptor.SingleTokenMatchGroup,
                    _descriptor.SingleToken!);
            }
            else
            {
                var hasMappings = _descriptor.MatchGroupsTokenMappings?.TryGetValue(mi, out mappings) ?? false;
                if (!hasMappings || mappings!.IsEmpty)
                {
                    if (!match.Success)
                    {
                        var range = lastRange == null ? operandLineRange : new Range(lastRange.Start, operandLineRange.End);
                        
                        return new AnalysedOperand(operandIndex, _descriptor, operandLineRange,
                           OperandResult.SyntaxError, range, resultTokens);
                    }

                    continue;
                }
            }

            foreach (var (groupIndex, token) in mappings!)
            {
                if (!match.Success)
                {
                    var range = lastRange == null ? operandLineRange : new Range(lastRange.Start, operandLineRange.End);
                    resultTokens.Add(new AnalysedOperandToken(token, OperandTokenResult.SyntaxError, range,
                        string.Empty));
                    
                    hasErrors = true;
                    mi = matches.Count;
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
                lastRange = tokenRange;

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

        return new AnalysedOperand(operandIndex, _descriptor, operandLineRange,
            hasErrors ? OperandResult.InvalidTokens : OperandResult.Valid, null, resultTokens);
    }
}
