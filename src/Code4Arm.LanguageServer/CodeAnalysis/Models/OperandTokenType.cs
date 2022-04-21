// OperandTokenType.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

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