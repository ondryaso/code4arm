using Code4Arm.LanguageServer.CodeAnalysis.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer.Services.Abstractions;

public interface IInstructionDocumentationProvider
{
    string InstructionDetail(InstructionVariant instructionVariant);
    MarkupContent? InstructionEntry(InstructionVariant instructionVariant);
    MarkupContent? InstructionOperandEntry(InstructionVariant instructionVariant, string tokenName);
}