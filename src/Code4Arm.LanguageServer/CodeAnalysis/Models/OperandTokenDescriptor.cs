// OperandTokenDescriptor.cs
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

/// <summary>
/// Represents a token of certain <see cref="OperandTokenType"/> in an operand descriptor.
/// A token is an atomic part of an operand syntax, such as a register name or shift type.
/// </summary>
/// <param name="Type">The <see cref="OperandTokenType"/> type of this token.</param>
/// <param name="SymbolicName">The name of the token shown in signature help.</param>
public record OperandTokenDescriptor(OperandTokenType Type, string SymbolicName)
{
    /// <summary>
    /// Allowed general-purpose registers for tokens of type <see cref="OperandTokenType.Register"/>. 
    /// </summary>
    public Register RegisterMask { get; init; } = RegisterExtensions.All;

    /// <summary>
    /// Determines the size in bits of an immediate constant when this token is of type <see cref="OperandTokenType.Immediate"/>.
    /// </summary>
    public int ImmediateSize { get; init; } = -1;

    /// <summary>
    /// Determines whether a token of type <see cref="OperandTokenType.Immediate"/> only allows values that are
    /// multiples of four.
    /// </summary>
    public bool IsImmediateDiv4 { get; init; } = false;

    /// <summary>
    /// Allowed shift types for tokens of type <see cref="OperandTokenType.ShiftType"/>.
    /// If null, all shift types are allowed.
    /// </summary>
    public ShiftType[]? AllowedShiftTypes { get; init; } = null;

    /// <summary>
    /// The <see cref="OperandTokenType"/> type of this token.
    /// </summary>
    public OperandTokenType Type { get; } = Type;
}
