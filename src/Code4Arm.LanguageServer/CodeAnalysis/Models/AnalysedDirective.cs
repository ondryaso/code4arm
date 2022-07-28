// AnalysedDirective.cs
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

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

public enum DirectiveType
{
    Type,
    Arch,
    ArchExtension,
    Code, // .code 16 / 32
    Cpu,
    TextSection,
    DataSection,
    BssSection,
    SetSymbol, // equ, set
    SetUndefinedSymbol, // equiv (signalling equ)
    EmitError,
    EmitWarning,
    Extern,
    Fill,
    Func,
    EndFunc,
    FnStart,
    FnEnd,
    Global,
    Include,
    Macro,
    Nop,
    Zero,
    HalfFloatFormat,
    ForceThumb,
    Thumb,
    ThumbFunc,
    Syntax,
    Size,
    // Emitting constants
    HalfFloat, // .float16
    SingleFloat, // .float, .single
    DoubleFloat, // .double
    Octa, // 256 b (16 B), .octa
    Quad, // 128 b (8 B), .quad
    Word, // 32 b, .word, .long, .int
    Short, // 16 b, .short, .hword
    Byte, // 8 b, .byte
    Space, // .skip, .space
    String,
    String8,
    String16,
    TwoBytes,
    FourBytes,
    EightBytes,
    Dc,
    Dcb,
    Ds,
    Ascii,
    AsciiZ,
    // Other
    Other
}

public enum DirectiveState
{
    Valid,
    UnknownDirective,
    UnknownType,
    InvalidDirectiveSyntax,
    InvalidSymbolName,
    InvalidConstant,
    NopDirective,
    InvalidArch,
    InvalidArchExtension,
    InvalidFloatFormat,
    ThumbUnsupported,
    DividedSyntaxUnsupported,
    UnquotedString
}

public record AnalysedDirective(DirectiveType Type, DirectiveState State, Range DirectiveRange, string DirectiveText, Range ParametersRange,
    string ParametersText, int ExpectedWidth = -1, DiagnosticSeverity Severity = DiagnosticSeverity.Error)
{
}
