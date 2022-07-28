// DwarfFileInformation.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// 
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// Copyright (c) 2019 Vuk Jovanovic
// 
// Original source: https://github.com/southpolenator/SharpDebug
// Available under the MIT License.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
// to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of
// the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

namespace Code4Arm.ExecutionCore.Dwarf;

/// <summary>
/// File metadata with line information
/// </summary>
public class DwarfFileInformation
{
    /// <summary>
    /// Gets or sets the file name.
    /// </summary>
    public string Name { get; init; }

    /// <summary>
    /// Gets or sets the directory.
    /// </summary>
    public string Directory { get; init; }

    /// <summary>
    /// Gets or sets the path.
    /// </summary>
    public string Path { get; init; }

    /// <summary>
    /// Gets or sets the last modification.
    /// </summary>
    public uint LastModification { get; init; }

    /// <summary>
    /// Gets or sets the length.
    /// </summary>
    public uint Length { get; init; }

    /// <summary>
    /// Gets or sets the lines information.
    /// </summary>
    public List<DwarfLineInformation> Lines { get; } = new();

    /// <summary>
    /// Returns a <see cref="System.String"/> that represents this instance.
    /// </summary>
    /// <returns>
    /// A <see cref="System.String"/> that represents this instance.
    /// </returns>
    public override string ToString() => Name;
}
