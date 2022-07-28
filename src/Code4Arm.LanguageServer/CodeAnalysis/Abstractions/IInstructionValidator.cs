// IInstructionValidator.cs
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

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

/// <summary>
/// Provides further validation of syntactically valid complete instruction lines.
/// </summary>
public interface IInstructionValidator
{
    /// <summary>
    /// Returns a <see cref="LineAnalysisState"/> value that is used as the final analysis result for a given line.
    /// </summary>
    /// <param name="line">The analysed line.</param>
    /// <param name="analysisState">The current line analysis model.</param>
    /// <param name="hasOperandsPart">True if the line contains operands.</param>
    LineAnalysisState ValidateInstruction(string line, AnalysedLine analysisState, bool hasOperandsPart);

    /// <summary>
    /// Determines whether a given vector data type may be used at a given position in a given line.
    /// </summary>
    /// <param name="specifierIndex">The specifier index.</param>
    /// <param name="type">The data type.</param>
    /// <param name="analysisState">The current line analysis model.</param>
    bool IsVectorDataTypeAllowed(int specifierIndex, VectorDataType type, AnalysedLine analysisState);

    /// <summary>
    /// Returns all vector data types that may be used at a given position in a given line.
    /// </summary>
    /// <param name="specifierIndex">The specifier index.</param>
    /// <param name="analysisState">The current line analysis model.</param>
    IEnumerable<VectorDataType> GetPossibleVectorDataTypes(int specifierIndex, AnalysedLine analysisState);
}
