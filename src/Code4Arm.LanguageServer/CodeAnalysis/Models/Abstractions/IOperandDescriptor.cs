// IOperandDescriptor.cs
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

using System.Text.RegularExpressions;

namespace Code4Arm.LanguageServer.CodeAnalysis.Models.Abstractions;

public interface IOperandDescriptor
{
    bool Optional { get; }

    OperandType Type { get; }

    OperandTokenDescriptor? SingleToken { get; }

    bool ShiftAllowed { get; }

    bool IsSingleToken { get; }

    InstructionVariant Mnemonic { get; }

    IEnumerable<Regex> Regexes { get; }

    bool HasCustomSignatureFormatting { get; }

    string? GetCustomSignatureFormatting();
    
    string? GetCustomSignatureFormatting(AnalysedLine lineAnalysis, AnalysedOperand analysedOperand);

    IEnumerable<OperandTokenDescriptor> GetTokenDescriptors();

    IEnumerable<OperandTokenDescriptor> GetTokenDescriptors(AnalysedLine lineAnalysis, AnalysedOperand analysedOperand);
}
