using Code4Arm.LanguageServer.CodeAnalysis.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer.Services.Abstractions;

/// <summary>
/// Provides documentation for instructions and operand tokens.
/// </summary>
public interface IInstructionDocumentationProvider
{
    /// <summary>
    /// Returns a short description of a given instruction variant. 
    /// </summary>
    string InstructionDetail(InstructionVariant instructionVariant);
    
    /// <summary>
    /// Returns the full documentation string for a given instruction variant.
    /// </summary>
    MarkupContent? InstructionEntry(InstructionVariant instructionVariant);
    
    /// <summary>
    /// Returns the full documentation of an operand token of a given instruction variant.
    /// </summary>
    MarkupContent? InstructionOperandEntry(InstructionVariant instructionVariant, string tokenName);
}
