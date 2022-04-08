// AnalysedOperand.cs
// Author: Ondřej Ondryáš

using System.Runtime.InteropServices;
using Armfors.LanguageServer.CodeAnalysis.Models.Abstractions;
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
    [FieldOffset(0)] public readonly AnalysedLabel? TargetLabel;
    [FieldOffset(8)] public readonly Register Register;
    [FieldOffset(8)] public readonly int Immediate;
    [FieldOffset(8)] public readonly ShiftType ShiftType;

    public AnalysedOperandTokenData(Register register)
    {
        Immediate = default;
        ShiftType = default;
        TargetLabel = default;
        Register = register;
    }

    public AnalysedOperandTokenData(ShiftType shiftType)
    {
        Immediate = default;
        Register = default;
        TargetLabel = default;
        ShiftType = shiftType;
    }

    public AnalysedOperandTokenData(int immediate)
    {
        ShiftType = default;
        Register = default;
        TargetLabel = default;
        Immediate = immediate;
    }
    
    public AnalysedOperandTokenData(AnalysedLabel targetLabel)
    {
        ShiftType = default;
        Register = default;
        Immediate = default;
        TargetLabel = targetLabel;
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

    public static implicit operator AnalysedOperandTokenData(AnalysedLabel analysedLabel)
    {
        return new AnalysedOperandTokenData(analysedLabel);
    }
}

public record AnalysedOperandToken(OperandTokenDescriptor TokenDescriptor, OperandTokenResult Result, Range Range, string Text,
    AnalysedOperandTokenData Data = default, DiagnosticSeverity Severity = DiagnosticSeverity.Error)
{
    public OperandTokenResult Result { get; set; } = Result;
    public OperandTokenType Type => this.TokenDescriptor.Type;
    public DiagnosticSeverity Severity { get; set; } = Severity;
    public AnalysedOperandTokenData Data { get; set; } = Data;
}

public record AnalysedOperand(int Index, IOperandDescriptor? Descriptor, Range Range, OperandResult Result,
    Range? ErrorRange = null, List<AnalysedOperandToken>? Tokens = null);

public record struct OperandMatchSet();
