// AnalysedSpecifier.cs
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

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

public class AnalysedSpecifier
{
    public bool IsInstructionSizeQualifier { get; }
    public bool IsVectorDataType { get; }

    public bool IsComplete { get; }
    public int VectorDataTypeIndex { get; } = -1;

    /// <summary>
    /// Determines whether this specifier is allowed at its position.
    /// </summary>
    public bool AllowedHere { get; }

    /// <summary>
    /// Determines the position of this specifier in the source text.
    /// </summary>
    public Range Range { get; }

    public VectorDataType VectorDataType { get; } = VectorDataType.Unknown;
    public InstructionSize InstructionSize { get; } = (InstructionSize)(-1);

    /// <summary>
    /// The actual textual representation of this specifier.
    /// </summary>
    public string Text { get; }

    public AnalysedSpecifier(string text, Range range, VectorDataType vectorDataType, int vectorDataTypeIndex,
        bool allowedHere = true)
    {
        this.AllowedHere = allowedHere;
        this.VectorDataTypeIndex = vectorDataTypeIndex;
        this.IsVectorDataType = true;
        this.VectorDataType = vectorDataType;
        this.Text = text;
        this.Range = range;
        this.IsComplete = true;
    }

    public AnalysedSpecifier(string text, Range range, InstructionSize instructionSize, bool allowedHere = true)
    {
        this.AllowedHere = allowedHere;
        this.IsInstructionSizeQualifier = true;
        this.InstructionSize = instructionSize;
        this.Text = text;
        this.Range = range;
        this.IsComplete = true;
    }

    public AnalysedSpecifier(string text, Range range)
    {
        this.Text = text;
        this.Range = range;
        this.AllowedHere = false;
        this.IsComplete = false;
    }
}