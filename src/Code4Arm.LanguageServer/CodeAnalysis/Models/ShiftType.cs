// Shift.cs
// Author: Ondřej Ondryáš

using System.Diagnostics.CodeAnalysis;

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum ShiftType
{
    LSL,
    LSR,
    ASR,
    ROR
}
