// ConditionCode.cs
// Author: Ondřej Ondryáš

using System.Diagnostics.CodeAnalysis;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

/// <summary>
/// A32 condition codes, values as defined in Armv8 Reference Manual, chapter F1.3.
/// </summary>
[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum ConditionCode
{
    EQ = 0,
    NE = 1,
    CS = 2,
    CC = 3,
    MI = 4,
    PL = 5,
    VS = 6,
    VC = 7,
    HI = 8,
    LS = 9,
    GE = 10,
    LT = 11,
    GT = 12,
    LE = 13,
    AL = 14,
    /// <summary>
    /// Indicates an invalid, or an uninitialized, condition code.
    /// </summary>
    Invalid = 15
}