// IInstructionProvider.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models;

namespace Armfors.LanguageServer.CodeAnalysis.Abstractions;

public interface IInstructionProvider
{
    /// <summary>
    /// Returns a list of all instructions. Different variants of the same mnemonic are returned as distinct
    /// <see cref="InstructionVariant"/> definitions.
    /// </summary>
    /// <returns></returns>
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
    /// <param name="mnemonic">The mnemonic to return variants for.</param>
    Task<List<InstructionVariant>> GetVariants(string mnemonic);
}
