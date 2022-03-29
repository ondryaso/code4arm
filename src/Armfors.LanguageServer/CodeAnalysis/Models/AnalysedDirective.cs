using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

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
    Equ, // equ, set
    Equiv, // equiv (signalling equ)
    Eqv, // like equiv -> signalling
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
    RedefinedLabel,
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