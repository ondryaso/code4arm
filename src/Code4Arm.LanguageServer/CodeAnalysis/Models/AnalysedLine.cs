// AnalysedLine.cs
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

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

public class AnalysedLine
{
    public Range AnalysedRange { get; }
    public int LineIndex => this.AnalysedRange.Start.Line;

    public int StartCharacter
    {
        get => this.AnalysedRange.Start.Character;
        set => this.AnalysedRange.Start.Character = value;
    }

    public int EndCharacter
    {
        get => this.AnalysedRange.End.Character;
        set => this.AnalysedRange.End.Character = value;
    }

    public int LineLength { get; init; }
    
    internal AnalysedLine(int line, int lineLength)
    {
        this.AnalysedRange = new Range(line, 0, line, 0);
        this.LineLength = lineLength;
    }

    /// <summary>
    /// The current analysis state of this line.
    /// </summary>
    public LineAnalysisState State { get; internal set; }

    /// <summary>
    /// The last analysis state before this line has been finished. 
    /// </summary>
    public LineAnalysisState PreFinishState { get; internal set; }
    
    public AnalysedDirective? Directive { get; internal set; }
    
    /// <summary>
    /// Mnemonics matching the current line's text.
    /// </summary>
    public List<InstructionVariant> MatchingMnemonics { get; internal set; } = new();

    public List<InstructionVariant> FullMatches { get; internal set; } = new();

    /// <summary>
    /// No mnemonic matches the line's text.
    /// </summary>
    public bool NoMatchingMnemonic => this.MatchingMnemonics.Count == 0;

    /// <summary>
    /// The recognised mnemonic (a full match).
    /// </summary>
    public InstructionVariant? Mnemonic { get; internal set; }

    /// <summary>
    /// A valid mnemonic has been recognised (<see cref="Mnemonic"/> is not null).
    /// </summary>
    public bool HasMnemonicMatch => this.Mnemonic != null;

    /// <summary>
    /// The line contains a mnemonic terminated with a whitespace.
    /// Flags have been read (or there isn't any).
    /// </summary>
    public bool MnemonicFinished { get; internal set; }

    /// <summary>
    /// The mnemonic describes the -S variant of an instruction that sets flags.
    /// </summary>
    public bool SetsFlags { get; internal set; }

    /// <summary>
    /// The instruction's condition code.
    /// </summary>
    public ConditionCode? ConditionCode { get; internal set; }

    public bool HasUnterminatedConditionCode { get; internal set; }
    public bool HasInvalidConditionCode { get; internal set; }

    /// <summary>
    /// The mnemonic describes a conditionally executed instruction (with valid loaded condition code).
    /// </summary>
    /// <remarks>
    /// This is equal to <see cref="ConditionCode"/> having a value.
    /// </remarks>
    public bool IsConditional => this.ConditionCode != null;

    /// <summary>
    /// The mnemonic contains a condition code (either valid or invalid).
    /// </summary>
    /// <remarks>
    /// This is equal to <see cref="ConditionCodeRange"/> having a value, or to one of <see cref="IsConditional"/>,
    /// <see cref="HasInvalidConditionCode"/>, <see cref="HasUnterminatedConditionCode"/> or <see cref="CannotBeConditional"/> being true.
    /// </remarks>
    /// <example>
    /// Suppose there's an unconditional instruction 'ABC' and a possibly conditional 'XYZ'.
    /// This would be true for: XYZEQ, XYZE, XYZEX, ABCEQ, ABCEQ, ABCE, ABCEX.
    /// </example>
    public bool HasConditionCodePart => this.ConditionCodeRange != null;

    public bool HasSpecifiers => this.Specifiers.Count > 0;

    /// <summary>
    /// A condition code has been provided but this instruction does not support it.
    /// </summary>
    public bool CannotBeConditional { get; internal set; }

    /// <summary>
    /// An S-suffixed variant of a mnemonic has been used but the instruction does not support settings flags.
    /// </summary>
    public bool CannotSetFlags { get; internal set; }

    /// <summary>
    /// Operands were used but the instruction does not support them.
    /// </summary>
    public bool NoOperandsAllowed { get; internal set; }

    /// <summary>
    /// Operands are required and they are missing.
    /// </summary>
    public bool MissingOperands { get; internal set; }
    
    /// <summary>
    /// Index to <see cref="Operands"/> determining the first invalid operand.
    /// </summary>
    public int ErroneousOperandIndex { get; internal set; }

    public Range? MnemonicRange { get; internal set; }
    public Range? SetFlagsRange { get; internal set; }
    public Range? ConditionCodeRange { get; internal set; }

    public List<AnalysedSpecifier> Specifiers { get; } = new();

    public List<AnalysedLabel> Labels { get; } = new();
    public List<AnalysedOperand>? Operands { get; internal set; }
}
