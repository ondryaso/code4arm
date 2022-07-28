// IInstructionProvider.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

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
