// IInstructionValidator.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.CodeAnalysis.Models;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

public interface IInstructionValidator
{
    LineAnalysisState ValidateInstruction(string line, AnalysedLine analysisState, bool hasOperandsPart);

    bool IsVectorDataTypeAllowed(int specifierIndex, VectorDataType type, AnalysedLine analysisState);

    IEnumerable<VectorDataType> GetPossibleVectorDataTypes(int specifierIndex, AnalysedLine analysisState);
}
