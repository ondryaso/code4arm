// IInstructionValidator.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models;

namespace Armfors.LanguageServer.CodeAnalysis.Abstractions;

public interface IInstructionValidator
{
    LineAnalysisState ValidateInstruction(string line, AnalysedLine analysisState, bool hasOperandsPart);

    bool IsVectorDataTypeAllowed(int specifierIndex, VectorDataType type, AnalysedLine analysisState);

    IEnumerable<VectorDataType> GetPossibleVectorDataTypes(int specifierIndex, AnalysedLine analysisState);
}
