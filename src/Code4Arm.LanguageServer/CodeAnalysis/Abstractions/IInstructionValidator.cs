// IInstructionValidator.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.CodeAnalysis.Models;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

/// <summary>
/// Provides further validation of syntactically valid complete instruction lines.
/// </summary>
public interface IInstructionValidator
{
    /// <summary>
    /// Returns a <see cref="LineAnalysisState"/> value that is used as the final analysis result for a given line.
    /// </summary>
    /// <param name="line">The analysed line.</param>
    /// <param name="analysisState">The current line analysis model.</param>
    /// <param name="hasOperandsPart">True if the line contains operands.</param>
    LineAnalysisState ValidateInstruction(string line, AnalysedLine analysisState, bool hasOperandsPart);

    /// <summary>
    /// Determines whether a given vector data type may be used at a given position in a given line.
    /// </summary>
    /// <param name="specifierIndex">The specifier index.</param>
    /// <param name="type">The data type.</param>
    /// <param name="analysisState">The current line analysis model.</param>
    bool IsVectorDataTypeAllowed(int specifierIndex, VectorDataType type, AnalysedLine analysisState);

    /// <summary>
    /// Returns all vector data types that may be used at a given position in a given line.
    /// </summary>
    /// <param name="specifierIndex">The specifier index.</param>
    /// <param name="analysisState">The current line analysis model.</param>
    IEnumerable<VectorDataType> GetPossibleVectorDataTypes(int specifierIndex, AnalysedLine analysisState);
}
