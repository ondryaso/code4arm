// IOperandDescriptor.cs
// Author: Ondřej Ondryáš

using System.Text.RegularExpressions;

namespace Armfors.LanguageServer.CodeAnalysis.Models.Abstractions;

public interface IOperandDescriptor
{
    bool Optional { get; }

    OperandType Type { get; }

    OperandTokenDescriptor? SingleToken { get; }

    bool ShiftAllowed { get; }

    bool IsSingleToken { get; }

    InstructionVariant Mnemonic { get; }

    IEnumerable<Regex> Regexes { get; }

    bool HasCustomSignatureFormatting { get; }

    string? GetCustomSignatureFormatting();
    
    string? GetCustomSignatureFormatting(AnalysedLine lineAnalysis, AnalysedOperand analysedOperand);

    IEnumerable<OperandTokenDescriptor> GetTokenDescriptors();

    IEnumerable<OperandTokenDescriptor> GetTokenDescriptors(AnalysedLine lineAnalysis, AnalysedOperand analysedOperand);
}
