// IInstructionProvider.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.CodeAnalysis.Models;
using Code4Arm.LanguageServer.CodeAnalysis.Models.Abstractions;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

/// <summary>
/// Provides instruction and operand definitions.
/// </summary>
public interface IInstructionProvider
{
    /// <summary>
    /// Returns a list of all instructions. Different variants of the same mnemonic are returned as distinct
    /// <see cref="InstructionVariant"/> definitions.
    /// </summary>
    Task<List<InstructionVariant>> GetAllInstructions();

    /// <summary>
    /// Finds all instructions that begin with a given text. Different variants of the same mnemonic are returned
    /// as distinct <see cref="InstructionVariant"/> definitions.
    /// </summary>
    /// <param name="line">The text to match instructions to.</param>
    Task<List<InstructionVariant>> FindMatchingInstructions(string line);

    /// <summary>
    /// Returns a list of all <see cref="InstructionVariant"/> definitions of a given mnemonic, i.e. definitions
    /// whose <see cref="InstructionVariant.Mnemonic"/> is equal to <paramref name="mnemonic"/>.
    /// </summary>
    /// <remarks>
    /// Variants whose <see cref="InstructionVariant.VariantFlags"/> match one or more bits set
    /// in <paramref name="exclude"/> will be excluded from the returned list.
    /// </remarks>
    /// <param name="mnemonic">The mnemonic to return variants for.</param>
    /// <param name="exclude">Flags specifying variants to exclude.</param>
    Task<List<InstructionVariant>?> GetVariants(string mnemonic,
        InstructionVariantFlag exclude = InstructionVariantFlag.NoFlags);

    /// <summary>
    /// Returns an enumerable of all operand descriptors for the given instruction variant.
    /// </summary>
    IEnumerable<IOperandDescriptor> GetOperands(InstructionVariant variant);
}
