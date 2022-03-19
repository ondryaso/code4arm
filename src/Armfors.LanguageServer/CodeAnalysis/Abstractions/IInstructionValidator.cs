// IInstructionValidator.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models;

namespace Armfors.LanguageServer.CodeAnalysis.Abstractions;

public interface IInstructionValidator
{
    LineAnalysisState ValidateInstruction(string line, AnalysedLine analysisState, bool hasOperandsPart);
}
