// IOperandAnalyser.cs
// Author: Ondřej Ondryáš

using System.Text.RegularExpressions;
using Code4Arm.LanguageServer.CodeAnalysis.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

public interface IOperandAnalyser
{
    AnalysedOperand AnalyseOperand(int operandIndex, int operandPartPositionInLine, List<Match> matches,
        Range operandLineRange, string operandLine);
}
