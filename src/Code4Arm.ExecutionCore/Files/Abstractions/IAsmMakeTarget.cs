// IAsmMakeTarget.cs
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

namespace Code4Arm.ExecutionCore.Files.Abstractions;

/// <summary>
/// An abstraction over a set of assembly source files that are assembled and linked together.
/// </summary>
public interface IAsmMakeTarget
{
    /// <summary>
    /// Returns an user-friendly identifier of this make target.
    /// </summary>
    string Name { get; }

    /// <summary>
    /// Returns an enumerable of make target files in linking order.
    /// </summary>
    IEnumerable<IAsmFile> GetFiles();

    /// <summary>
    /// Returns a make target file of given <paramref name="name"/>.
    /// </summary>
    /// <param name="name">The name of the make target file.</param>
    /// <returns>The make target ASM file or null if no such file exists.</returns>
    IAsmFile? GetFile(string name);
}
