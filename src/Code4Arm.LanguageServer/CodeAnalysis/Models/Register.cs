// Register.cs
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
using Code4Arm.LanguageServer.Extensions;

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

[SuppressMessage("ReSharper", "InconsistentNaming")]
[Flags]
public enum Register
{
    R0 = 1 << 0,
    R1 = 1 << 1,
    R2 = 1 << 2,
    R3 = 1 << 3,
    R4 = 1 << 4,
    R5 = 1 << 5,
    R6 = 1 << 6,
    R7 = 1 << 7,
    R8 = 1 << 8,
    R9 = 1 << 9,
    R10 = 1 << 10,
    R11 = 1 << 11,
    R12 = 1 << 12,
    SP = 1 << 13,
    LR = 1 << 14,
    PC = 1 << 15
}

public static class RegisterExtensions
{
    public const Register All = (Register)((1 << 16) - 1);
    public const Register General = (Register)((1 << 13) - 1);

    // ReSharper disable once InconsistentNaming
    public const Register WithoutPC = (Register)((1 << 15) - 1);

    /// <summary>
    /// Determines whether a <see cref="Register"/> bitfield value only marks a single register.
    /// </summary>
    /// <example>
    /// <code>
    /// (Register.R0 | Register.R1).IsSingleRegister() == false
    /// Register.R0.IsSingleRegister() == true
    /// </code>
    /// </example>
    /// <param name="register">The register value.</param>
    /// <returns>True if </returns>
    public static bool IsSingleRegister(this Register register)
    {
        var regNumber = (uint)register;
        if (regNumber == 0)
            return false;

        return (regNumber & (~(regNumber - 1))) == regNumber;
    }

    /// <summary>
    /// Returns the index of a given <see cref="Register"/> (e.g. 2 for R2).
    /// </summary>
    /// <param name="register">The register.</param>
    /// <returns>The register's index number.</returns>
    public static int GetIndex(this Register register)
    {
        return (int)Math.Log2((double)register);
    }

    public static bool TryParseRegister(string name, out Register register)
    {
        var isBasicName = EnumExtensions.TryParseName(name, out register);
        if (isBasicName)
            return true;
        
        if (name.Equals("R13", StringComparison.InvariantCultureIgnoreCase))
        {
            register = Register.SP;
            return true;
        }
        
        if (name.Equals("R14", StringComparison.InvariantCultureIgnoreCase))
        {
            register = Register.LR;
            return true;
        }
        
        if (name.Equals("R15", StringComparison.InvariantCultureIgnoreCase))
        {
            register = Register.PC;
            return true;
        }

        return false;
    }
}
