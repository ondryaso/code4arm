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
    /// <summary>
    /// Equal.
    /// </summary>
    EQ = 0,

    /// <summary>
    /// Not equal / Not equal or unordered (FP).
    /// </summary>
    NE = 1,

    /// <summary>
    /// Carry set / Greater than, equal or unordered (FP).
    /// </summary>
    CS = 2,

    /// <summary>
    /// Carry clear / Less than (FP).
    /// </summary>
    CC = 3,

    /// <summary>
    /// Minus, negative / Less than (FP).
    /// </summary>
    MI = 4,

    /// <summary>
    /// Plus, positive or zero / Greater than, equal or unordered (FP).
    /// </summary>
    PL = 5,

    /// <summary>
    /// Overflow / Unordered (FP).
    /// </summary>
    VS = 6,

    /// <summary>
    /// No overflow / Not unordered (FP).
    /// </summary>
    VC = 7,

    /// <summary>
    /// Unsigned higher / Greater than or unordered (FP).
    /// </summary>
    HI = 8,

    /// <summary>
    /// Unsigned lower or same / Less than or equal (FP).
    /// </summary>
    LS = 9,

    /// <summary>
    /// Signed greater than or equal / Greater than or equal (FP).
    /// </summary>
    GE = 10,

    /// <summary>
    /// Signed less than / Less than or unordered (FP).
    /// </summary>
    LT = 11,

    /// <summary>
    /// Signed greater than / Greater than (FP).
    /// </summary>
    GT = 12,

    /// <summary>
    /// Signed less than or equal / Less than, equal or unordered (FP).
    /// </summary>
    LE = 13,

    /// <summary>
    /// Always.
    /// </summary>
    AL = 14,

    /// <summary>
    /// Indicates an invalid, or an uninitialized, condition code.
    /// </summary>
    Invalid = 15,

    /// <summary>
    /// Unsigned higher or same. Synonym for CS.
    /// </summary>
    HS = 16 | 2,

    /// <summary>
    /// Unsigned lower. Synonym for CC.
    /// </summary>
    LO = 16 | 3
}
