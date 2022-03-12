// AnalysedOperand.cs
// Author: Ondřej Ondryáš

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
    InvalidRegisterList,
    RegisterListMustContainPc,
    RegisterListCannotContainPc,
    InvalidAlignment,
    InvalidSpecialOperand,
}

public enum OperandResult
{
    Valid,
    InvalidTokens,
    UnexpectedOperand,
    MissingOperand,
    SyntaxError
}

public record struct AnalysedOperandToken(OperandTokenType Type, OperandTokenResult Result, Range Range, string Text,
    bool WarningOnly = false);

public record AnalysedOperand(int Index, OperandDescriptor? Descriptor, Range Range, OperandResult Result,
    Range? ErrorRange = null, List<AnalysedOperandToken>? Tokens = null);
