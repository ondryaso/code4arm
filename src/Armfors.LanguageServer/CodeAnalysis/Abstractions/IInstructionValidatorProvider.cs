// IInstructionValidatorProvider.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models;

namespace Armfors.LanguageServer.CodeAnalysis.Abstractions;

public interface IInstructionValidatorProvider
{
    IInstructionValidator? For(InstructionVariant instructionVariant);
}
