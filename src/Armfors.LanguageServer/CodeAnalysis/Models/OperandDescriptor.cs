// OperandVariant.cs
// Author: Ondřej Ondryáš

using System.Collections.Immutable;
using System.Text.RegularExpressions;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

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

    public OperandToken? SingleToken =>
        _singleToken ? this.MatchGroupsTokenMappings[0][this.SingleTokenMatchGroup] : null;

    public int SingleTokenMatchGroup { get; }

    /// <summary>
    /// Determines whether shifting is allowed.
    /// Used with register addressing (LDR can shift the offset register, LDRD cannot).
    /// </summary>
    public bool ShiftAllowed { get; } = false;

    public bool IsSingleToken => _singleToken;

    private readonly bool _singleToken;

    public ImmutableDictionary<int, ImmutableDictionary<int, OperandToken>> MatchGroupsTokenMappings { get; }

    public InstructionVariant Mnemonic { get; }

    private readonly List<Regex> _regexes;
    public IEnumerable<Regex> Regexes => _regexes;

    public string? TokenFormatting { get; init; }

    private OperandDescriptor(InstructionVariant mnemonic, OperandType type)
    {
        this.Type = type;
        this.Mnemonic = mnemonic;

        _regexes = null!;
        this.MatchGroupsTokenMappings = null!;

        if (type == OperandType.ImmediateAddressing)
        {
            this.TokenFormatting = "[ {0} {{, {1}}} ]";
        }
        else if (type == OperandType.RegisterAddressing)
        {
            this.TokenFormatting = "[ {0},  {1} ]";
        }
    }

    public OperandDescriptor(InstructionVariant mnemonic, string literal) : this(mnemonic, OperandType.Literal)
    {
        this.Optional = false;
        this.MatchGroupsTokenMappings = ImmutableDictionary<int, ImmutableDictionary<int, OperandToken>>.Empty;
        _regexes = new List<Regex> { new("\\G" + literal, RegexOptions.Compiled) };
    }

    public OperandDescriptor(InstructionVariant mnemonic, string regex, OperandType type, OperandTokenType tokenType,
        string tokenName, int singleTokenMatchGroup = 1, bool optional = false) : this(mnemonic, type)
    {
        this.Optional = optional;

        _singleToken = true;
        this.SingleTokenMatchGroup = singleTokenMatchGroup;

        this.MatchGroupsTokenMappings = ImmutableDictionary<int, ImmutableDictionary<int, OperandToken>>.Empty
            .Add(0, ImmutableDictionary<int, OperandToken>.Empty.Add(singleTokenMatchGroup,
                new OperandToken(tokenType, tokenName)));

        _regexes = new List<Regex> { new(regex, RegexOptions.Compiled) };
    }

    public OperandDescriptor(InstructionVariant mnemonic, IEnumerable<string> matches, OperandType type, bool optional,
        params (int RegexIndex, int MatchGroup, OperandToken Token)[] tokens) : this(mnemonic, type)
    {
        this.Optional = optional;

        this.MatchGroupsTokenMappings = tokens.GroupBy(t => t.RegexIndex)
            .ToImmutableDictionary(g => g.Key,
                g => g.ToImmutableDictionary(a => a.MatchGroup,
                    a => a.Token));

        _regexes = matches.Select(m => new Regex(m, RegexOptions.Compiled)).ToList();
    }

    public OperandDescriptor(InstructionVariant mnemonic, string regex, OperandType type, bool optional,
        params (int, int, OperandToken)[] tokens) : this(mnemonic, new[] { regex }, type, optional, tokens)
    {
    }
}
