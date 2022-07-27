// IOperandAnalyser.cs
// Author: Ondřej Ondryáš

using System.Text.RegularExpressions;
using Code4Arm.LanguageServer.CodeAnalysis.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

/// <summary>
/// Analyses operands.
/// </summary>
public interface IOperandAnalyser
{
    /// <summary>
    /// Analyse an operand based on the regular expressions matches and returns an <see cref="AnalysedOperand"/> object
    /// with the analysis results. 
    /// </summary>
    /// <param name="operandIndex">The index of the operand descriptor.</param>
    /// <param name="operandPartPositionInLine">The line index of the start of the operands part in the instruction line
    /// (that is, the index where <paramref name="operandLine"/> starts in the original line).</param>
    /// <param name="matches">A list of <see cref="Match"/> objects describing the results of matching the regexes
    /// provided by the operand descriptor.</param>
    /// <param name="operandLineRange">The range of the analysed operand in the <paramref name="operandLine"/>.</param>
    /// <param name="operandLine">A string with only the operand part of the current line.</param>
    /// <returns></returns>
    AnalysedOperand AnalyseOperand(int operandIndex, int operandPartPositionInLine, List<Match> matches,
        Range operandLineRange, string operandLine);
}
