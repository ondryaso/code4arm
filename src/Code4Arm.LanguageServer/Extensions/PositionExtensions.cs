// PositionExtensions.cs
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

namespace Code4Arm.LanguageServer.Extensions;

public static class PositionExtensions
{
    /// <summary>
    /// Copies position data from one <see cref="Position"/> object to another.
    /// </summary>
    /// <param name="position">The object to put data into.</param>
    /// <param name="other">The object to take data from.</param>
    public static void CopyFrom(this Position position, Position other)
    {
        position.Character = other.Character;
        position.Line = other.Line;
    }
}
