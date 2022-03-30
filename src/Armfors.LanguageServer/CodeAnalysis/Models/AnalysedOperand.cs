// AnalysedOperand.cs
// Author: Ondřej Ondryáš

using System.Runtime.InteropServices;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

public enum OperandTokenResult
{
    Valid,
    InvalidRegister,
    InvalidImmediateValue,
    InvalidImmediateConstantValue,
    ImmediateConstantNegative,
    InvalidShiftType,
    InvalidRegisterListEntry,
    RegisterListMustContainPc,
    RegisterListCannotContainPc,
    InvalidAlignment,
    InvalidSpecialOperand,
    UndefinedLabel,
    SyntaxError
}

public enum OperandResult
{
    Valid,
    InvalidTokens,
    UnexpectedOperand,
    MissingOperand,
    SyntaxError
}

[StructLayout(LayoutKind.Explicit)]
public readonly struct AnalysedOperandTokenData
{
    [FieldOffset(0)] public readonly Register Register;
    [FieldOffset(0)] public readonly int Immediate;
    [FieldOffset(0)] public readonly ShiftType ShiftType;

    public AnalysedOperandTokenData(Register register)
    {
        Immediate = default;
        ShiftType = default;
        Register = register;
    }

    public AnalysedOperandTokenData(ShiftType shiftType)
    {
        Immediate = default;
        Register = default;
        ShiftType = shiftType;
    }

    public AnalysedOperandTokenData(int immediate)
    {
        ShiftType = default;
        Register = default;
        Immediate = immediate;
    }

    public static implicit operator AnalysedOperandTokenData(Register register)
    {
        return new AnalysedOperandTokenData(register);
    }

    public static implicit operator AnalysedOperandTokenData(int immediate)
    {
        return new AnalysedOperandTokenData(immediate);
    }

    public static implicit operator AnalysedOperandTokenData(ShiftType shiftType)
    {
        return new AnalysedOperandTokenData(shiftType);
    }
}

public record AnalysedOperandToken(OperandToken Token, OperandTokenResult Result, Range Range, string Text,
    AnalysedOperandTokenData Data = default, DiagnosticSeverity Severity = DiagnosticSeverity.Error)
{
    public OperandTokenResult Result { get; set; } = Result;
    public OperandTokenType Type => this.Token.Type;
    public DiagnosticSeverity Severity { get; set; } = Severity;
}

public record AnalysedOperand(int Index, OperandDescriptor? Descriptor, Range Range, OperandResult Result,
    Range? ErrorRange = null, List<AnalysedOperandToken>? Tokens = null);

public record struct OperandMatchSet();