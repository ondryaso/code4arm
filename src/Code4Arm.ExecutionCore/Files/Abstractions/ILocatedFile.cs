// ILocatedFile.cs
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
/// Represents a 'disposable filesystem path'. When acquiring an instance of <see cref="ILocatedFile"/>, the owner can
/// presume that a <see cref="IAsmFile"/> representation is saved in the filesystem, at the path given by
/// <see cref="FileSystemPath"/>.
/// When finished working with it, the <see cref="ILocatedFile"/> instance should be disposed which provides way of
/// cleaning
/// up the file if it was only temporary.
/// </summary>
public interface ILocatedFile : IDisposable
{
    /// <summary>
    /// The path of the filesystem representation of <see cref="File"/>.
    /// </summary>
    string FileSystemPath { get; }

    /// <summary>
    /// The version of <see cref="File"/> saved in the filesystem. This may not correspond with the value of the
    /// <see cref="IAsmFile.Version"/> property of <see cref="File"/>, in which case the caller may dispose this
    /// <see cref="ILocatedFile"/> and request a new one.
    /// </summary>
    int Version { get; }

    /// <summary>
    /// The <see cref="IAsmFile"/> that is the source of this representation.
    /// </summary>
    IAsmFile File { get; }
}
