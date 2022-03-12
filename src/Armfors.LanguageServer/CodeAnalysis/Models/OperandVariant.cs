// OperandVariant.cs
// Author: Ondřej Ondryáš

using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum OperandType
{
    Register, // A general-purpose register
    Immediate, // <immX> where X is the bit width of the immediate
    ImmediateDiv4, // <immX> which is a multiple of 4 (so if X=5b, the range is 0 to 2^5*4)
    ImmediateConstant, // #<const>, see "Modified immediate constants" in F1.7.7 (p4363) and J1.2 (p8170)
    ShiftType, // LSL/LSR/ASR/ROR
    Literal, // Anything to match literally (e.g. CSYNC)
    ImmediateAddressing, // any of ImmediateOffset, ImmediatePostIndexed or ImmediatePreIndexed
    ImmediateOffset, // [<Rn> {, #{+/-}<imm>}]
    ImmediatePostIndexed, // [<Rn>], #{+/-}<imm>
    ImmediatePreIndexed, // [<Rn> {, #{+/-}<imm>}]!
    RegisterAddressing, // any of RegisterOffset, RegisterPostIndexed or RegisterPostIndexed
    RegisterOffset, // [<Rn>, #{+/-}<Rm> {, <shift> <imm>}]
    RegisterPostIndexed, // [<Rn>], #{+/-}<Rm> {, <shift> <imm>}
    RegisterPreIndexed, // [<Rn>, #{+/-}<Rm> {, <shift> <imm>}]!
    Label, // <label>
    RRX,
    RegisterList, // <registers_without_pc> (set reg. mask) or <registers>
    RegisterListWithPC, // <registers_with_pc> 
    SimdSingleRegister, // <Sm>
    SimdDoubleRegister, // <Dm>
    SimdQuadRegister, // <Qm>
    SimdSingleRegisterIndexed, // <Sm>[index]
    SimdDoubleRegisterIndexed, // <Dm>[index]
    RegisterWithAlignmentAddressing, // [<Rn>{:<align>}]{!} / [<Rn>{:<align>}], <Rm>; see F1.9.2
    SimdVectorList, // <list>; see F1.9.7
    SimdSingleRegisterList, // <sreglist>
    SimdDoubleRegisterList, // <dreglist>
    SimdSpecialRegister // FPSID, FPSCR, MVFR2, MVFR1, MVFR0, FPEXC (VMRS instr.)
}

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

/// <summary>
/// Represents a token of certain <see cref="OperandTokenType"/> in an operand descriptor.
/// A token is an atomic part of an operand syntax, such as a register name or shift type.
/// </summary>
/// <param name="Type">The <see cref="OperandTokenType"/> type of this token.</param>
public record OperandToken(OperandTokenType Type)
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

/// <summary>
/// Describes a possible operand of a certain <see cref="InstructionVariant"/>.
/// </summary>
/// <remarks>
/// An operand descriptor defines a regular expression that can be used to match the operand in a source text.
/// The descriptor may describe an atomic expression, such as a label, or a composed expression that must appear
/// whole in the text to be a valid operand, such as a post-index addressing expression. Operand descriptors thus
/// define a collection of <see cref="OperandToken"/> descriptors that further specify these atomic parts of an
/// operand. It is stored in the <see cref="MatchGroupsTokenMappings"/> dictionary where keys are indexes to the
/// descriptor's regex match groups. If a descriptor describes a sole atomic expression, its <see cref="SingleToken"/>
/// is populated instead of the dictionary. 
/// </remarks>
public class OperandDescriptor
{
    public bool Optional { get; }

    public OperandType Type { get; }

    public OperandToken? SingleToken { get; }
    
    public int SingleTokenMatchGroup { get; }

    /// <summary>
    /// Determines whether shifting is allowed.
    /// Used with register addressing (LDR can shift the offset register, LDRD cannot).
    /// </summary>
    public bool ShiftAllowed { get; } = false;

    public bool IsSingleToken => this.SingleToken != null;

    public ImmutableDictionary<int, OperandToken>? MatchGroupsTokenMappings { get; }

    public InstructionVariant Mnemonic { get; set; }

    private Regex? _regex = null;
    public Regex Regex => _regex ?? this.MakeRegex();

    public OperandDescriptor(string match, OperandType type, OperandTokenType? tokenType, bool optional = false, int stmg = 0)
    {
        this.Mnemonic = null;

        this.Optional = optional;
        this.Type = type;

        if (tokenType.HasValue)
        {
            this.SingleToken = new OperandToken(tokenType.Value);
            this.SingleTokenMatchGroup = stmg;
        }
        else
        {
            this.MatchGroupsTokenMappings = ImmutableDictionary<int, OperandToken>.Empty.AddRange(new[]
            {
                new KeyValuePair<int, OperandToken>(1, new OperandToken(OperandTokenType.Register)),
                new KeyValuePair<int, OperandToken>(3,
                    new OperandToken(OperandTokenType.Immediate) { ImmediateSize = 4 })
            });
        }

        _regex = new Regex(match, RegexOptions.Compiled);
    }

    private Regex MakeRegex()
    {
        _regex = new Regex(".*", RegexOptions.Compiled);
        return _regex;
    }
}
