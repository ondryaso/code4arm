// ConditionCode.cs
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

using System.Diagnostics.CodeAnalysis;

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

/// <summary>
/// A32 condition codes, values as defined in Armv8 Reference Manual, chapter F1.3.
/// </summary>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum ConditionCode
{
    /// <summary>
    /// Equal.
    /// </summary>
    EQ = 0,

    /// <summary>
    /// Not equal / Not equal or unordered (FP).
    /// </summary>
    NE = 1,

    /// <summary>
    /// Carry set / Greater than, equal or unordered (FP).
    /// </summary>
    CS = 2,

    /// <summary>
    /// Carry clear / Less than (FP).
    /// </summary>
    CC = 3,

    /// <summary>
    /// Minus, negative / Less than (FP).
    /// </summary>
    MI = 4,

    /// <summary>
    /// Plus, positive or zero / Greater than, equal or unordered (FP).
    /// </summary>
    PL = 5,

    /// <summary>
    /// Overflow / Unordered (FP).
    /// </summary>
    VS = 6,

    /// <summary>
    /// No overflow / Not unordered (FP).
    /// </summary>
    VC = 7,

    /// <summary>
    /// Unsigned higher / Greater than or unordered (FP).
    /// </summary>
    HI = 8,

    /// <summary>
    /// Unsigned lower or same / Less than or equal (FP).
    /// </summary>
    LS = 9,

    /// <summary>
    /// Signed greater than or equal / Greater than or equal (FP).
    /// </summary>
    GE = 10,

    /// <summary>
    /// Signed less than / Less than or unordered (FP).
    /// </summary>
    LT = 11,

    /// <summary>
    /// Signed greater than / Greater than (FP).
    /// </summary>
    GT = 12,

    /// <summary>
    /// Signed less than or equal / Less than, equal or unordered (FP).
    /// </summary>
    LE = 13,

    /// <summary>
    /// Always.
    /// </summary>
    AL = 14,

    /// <summary>
    /// Indicates an invalid, or an uninitialized, condition code.
    /// </summary>
    Invalid = 15,

    /// <summary>
    /// Unsigned higher or same. Synonym for CS.
    /// </summary>
    HS = 16 | 2,

    /// <summary>
    /// Unsigned lower. Synonym for CC.
    /// </summary>
    LO = 16 | 3
}
