// OperandTokenType.cs
// Author: Ondřej Ondryáš

namespace Armfors.LanguageServer.CodeAnalysis.Models;

public enum OperandTokenType
{
    Immediate,
    ImmediateConstant,
    ImmediateShift,
    Register,
    SimdRegister,
    Label,
    ShiftType
}