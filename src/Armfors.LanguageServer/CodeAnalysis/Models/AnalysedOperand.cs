// AnalysedOperand.cs
// Author: Ondřej Ondryáš

namespace Armfors.LanguageServer.CodeAnalysis.Models;

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

public enum OperandResult
{
    Valid,
    InvalidRegister,
    InvalidImmediateValue,
    InvalidShiftType,
    InvalidRegisterList,
    RegisterListMustContainPc,
    RegisterListCannotContainPc,
    InvalidAlignment,
    InvalidSpecialOperand,
    UnexpectedOperand,
    SyntaxError
}

public record struct AnalysedOperandToken(OperandTokenType Type, Range Range);

public record AnalysedOperand(int Index, OperandDescriptor? Descriptor, Range Range, OperandResult Result,
    Range? ErrorRange = null, List<AnalysedOperandToken>? Tokens = null);
