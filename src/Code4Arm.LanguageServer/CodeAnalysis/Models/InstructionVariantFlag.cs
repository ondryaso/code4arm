// InstructionVariantFlag.cs
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

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

[Flags]
public enum InstructionVariantFlag
{
    /// <summary>
    /// The instruction variant has no special usage flags.
    /// </summary>
    NoFlags = 0,
    /// <summary>
    /// The instruction is a SIMD/FP instruction.
    /// </summary>
    Simd = 1 << 0,
    /// <summary>
    /// The instruction is uncommon – students should learn about them but not right at the beginning.
    /// This includes some less used ALU operations like saturating add.
    /// </summary>
    UncommonInstruction = 1 << 1,
    /// <summary>
    /// The instruction is advanced – Arm beginner students are not expected to use them.
    /// </summary>
    AdvancedInstruction = 1 << 2,
    /// <summary>
    /// Other variants of the instruction may not be flagged but this one is not a common one. 
    /// </summary>
    UncommonVariant = 1 << 3
}
