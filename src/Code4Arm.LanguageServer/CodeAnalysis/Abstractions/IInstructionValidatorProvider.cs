// IInstructionValidatorProvider.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.CodeAnalysis.Models;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

/// <summary>
/// Provides <see cref="IInstructionValidator"/> instances for <see cref="InstructionVariant"/> objects.
/// </summary>
public interface IInstructionValidatorProvider
{
    /// <summary>
    /// Create a <see cref="IInstructionValidator"/> instance for a given instruction variant.
    /// If null is returned, the instruction doesn't require final validation.
    /// </summary>
    IInstructionValidator? For(InstructionVariant instructionVariant);
}
