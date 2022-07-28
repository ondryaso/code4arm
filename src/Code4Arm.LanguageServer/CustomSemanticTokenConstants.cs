// CustomSemanticTokenConstants.cs
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

using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer;

/// <summary>
/// Contains definitions of custom <see cref="SemanticTokenType"/> objects.
/// </summary>
public static class ArmSemanticTokenType
{
    /// An instruction mnemonic.
    public static readonly SemanticTokenType Instruction = new("instruction");

    /// An assembler directive.
    public static readonly SemanticTokenType Directive = new("directive");
    
    /// An Arm UAL shift type (LSL/LSR/ASR/ROR/RRX).
    public static readonly SemanticTokenType ShiftType = new("shift_type");

    /// A register.
    public static readonly SemanticTokenType Register = new("register");

    /// A condition code appended to an instruction mnemonic.
    public static readonly SemanticTokenType ConditionCode = new("condition_code");

    /// A flag appended to an instruction mnemonic that controls if the instruction sets processor flags.
    public static readonly SemanticTokenType SetsFlagsFlag = new("sets_flags_flag");

    /// A vector data type flag.
    public static readonly SemanticTokenType VectorDataType = new("vector_data_type");
    
    /// An instruction size qualifier (.W/.N).
    public static readonly SemanticTokenType InstructionSizeQualifier = new("instruction_size_qualifier");
}

/// <summary>
/// Contains definitions of custom <see cref="SemanticTokenModifier"/> objects.
/// </summary>
public static class ArmSemanticTokenModifier
{
    /// Marks an instruction that is executed conditionally.
    public static readonly SemanticTokenModifier Conditional = new("conditional");

    /// Marks an instruction that controls if the instruction sets processor flags.
    public static readonly SemanticTokenModifier SetsFlags = new("sets_flags");

    /// Marks a SIMD/FP instruction.
    public static readonly SemanticTokenModifier VectorInstruction = new("vector_instruction");

    /// Marks a SIMD/FP register.
    public static readonly SemanticTokenModifier VectorRegister = new("vector_register");
    
    /// Marks a simulated function label.
    public static readonly SemanticTokenModifier SimulatedFunction = new("simulated_function");
    
    public static IEnumerable<SemanticTokenModifier> All => new[]
    {
        Conditional, SetsFlags, VectorInstruction
    };
}
