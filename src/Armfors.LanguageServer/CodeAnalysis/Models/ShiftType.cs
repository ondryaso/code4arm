// ShiftType.cs
// Author: Ondřej Ondryáš

using System.Diagnostics.CodeAnalysis;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum ShiftType
{
    LSL,
    LSR,
    ASR,
    ROR
}
