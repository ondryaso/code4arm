// OperandToken.cs
// Author: Ondřej Ondryáš

namespace Armfors.LanguageServer.CodeAnalysis.Models;

/// <summary>
/// Represents a token of certain <see cref="OperandTokenType"/> in an operand descriptor.
/// A token is an atomic part of an operand syntax, such as a register name or shift type.
/// </summary>
/// <param name="Type">The <see cref="OperandTokenType"/> type of this token.</param>
/// <param name="SymbolicName">The name of the token shown in signature help.</param>
public record OperandToken(OperandTokenType Type, string SymbolicName)
{
    /// <summary>
    /// Allowed general-purpose registers for tokens of type <see cref="OperandTokenType.Register"/>. 
    /// </summary>
    public Register RegisterMask { get; init; } = RegisterExtensions.All;

    /// <summary>
    /// Determines the size in bits of an immediate constant when this token is of type <see cref="OperandTokenType.Immediate"/>.
    /// </summary>
    public int ImmediateSize { get; init; } = -1;

    /// <summary>
    /// Determines whether a token of type <see cref="OperandTokenType.Immediate"/> only allows values that are
    /// multiples of four.
    /// </summary>
    public bool IsImmediateDiv4 { get; init; } = false;

    /// <summary>
    /// Allowed shift types for tokens of type <see cref="OperandTokenType.ShiftType"/>.
    /// If null, all shift types are allowed.
    /// </summary>
    public ShiftType[]? AllowedShiftTypes { get; init; } = null;

    /// <summary>
    /// The <see cref="OperandTokenType"/> type of this token.
    /// </summary>
    public OperandTokenType Type { get; } = Type;
}