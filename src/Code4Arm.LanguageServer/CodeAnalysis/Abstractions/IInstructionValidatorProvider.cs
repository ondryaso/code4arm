// IInstructionValidatorProvider.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.CodeAnalysis.Models;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

public interface IInstructionValidatorProvider
{
    IInstructionValidator? For(InstructionVariant instructionVariant);
}
