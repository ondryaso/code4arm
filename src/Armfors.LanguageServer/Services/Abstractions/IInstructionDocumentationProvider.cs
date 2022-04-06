using Armfors.LanguageServer.CodeAnalysis.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Services.Abstractions;

public interface IInstructionDocumentationProvider
{
    string InstructionDetail(InstructionVariant instructionVariant);
    MarkupContent? InstructionEntry(InstructionVariant instructionVariant);
    MarkupContent? InstructionOperandEntry(InstructionVariant instructionVariant, string tokenName);
}