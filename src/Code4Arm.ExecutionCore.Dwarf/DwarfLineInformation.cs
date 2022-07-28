// DwarfLineInformation.cs
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
/// Information about line containing compiled code.
/// </summary>
public record struct DwarfLineInformation
{
    /// <summary>
    /// Gets or sets the file information.
    /// </summary>
    public DwarfFileInformation File { get; init; }

    /// <summary>
    /// Gets or sets the relative module address.
    /// </summary>
    public uint Address { get; init; }

    /// <summary>
    /// Gets or sets the line.
    /// </summary>
    public uint Line { get; init; }

    /// <summary>
    /// Gets or sets the column.
    /// </summary>
    public uint Column { get; init; }
}
