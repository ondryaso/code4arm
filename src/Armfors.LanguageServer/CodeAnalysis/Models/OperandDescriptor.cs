// OperandVariant.cs
// Author: Ondřej Ondryáš

using System.Collections.Immutable;
using System.Text.RegularExpressions;
using Armfors.LanguageServer.CodeAnalysis.Models.Abstractions;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

/// <summary>
/// Describes a possible operand of a certain <see cref="InstructionVariant"/>.
/// </summary>
/// <remarks>
/// An operand descriptor defines a regular expression that can be used to match the operand in a source text.
/// The descriptor may describe an atomic expression, such as a label, or a composed expression that must appear
/// whole in the text to be a valid operand, such as a post-index addressing expression. Operand descriptors thus
/// define a collection of <see cref="OperandTokenDescriptor"/> descriptors that further specify these atomic parts of an
/// operand. It is stored in the <see cref="MatchGroupsTokenMappings"/> dictionary where keys are indexes to the
/// descriptor's regex match groups. If a descriptor describes a sole atomic expression, its <see cref="SingleToken"/>
/// is populated instead of the dictionary. 
/// </remarks>
public class BasicOperandDescriptor : IOperandDescriptor
{
    public bool Optional { get; }

    public OperandType Type { get; }

    public OperandTokenDescriptor? SingleToken =>
        _singleToken ? this.MatchGroupsTokenMappings[0][this.SingleTokenMatchGroup] : null;

    public int SingleTokenMatchGroup { get; }

    /// <summary>
    /// Determines whether shifting is allowed.
    /// Used with register addressing (LDR can shift the offset register, LDRD cannot).
    /// </summary>
    public bool ShiftAllowed { get; } = false;

    public bool IsSingleToken => _singleToken;

    private readonly bool _singleToken;

    public ImmutableDictionary<int, ImmutableDictionary<int, OperandTokenDescriptor>> MatchGroupsTokenMappings { get; }

    public InstructionVariant Mnemonic { get; }

    private readonly List<Regex> _regexes;
    public IEnumerable<Regex> Regexes => _regexes;

    public bool HasCustomSignatureFormatting => this.CustomSignatureFormatting != null;

    public string? GetCustomSignatureFormatting()
    {
        if (this.CustomSignatureFormatting == null)
            return null;

        return string.Format(this.CustomSignatureFormatting!,
            this.GetTokenDescriptors().Select(t => $"<{t.SymbolicName}>" as object).ToArray());
    }

    public string? GetCustomSignatureFormatting(AnalysedLine lineAnalysis, AnalysedOperand analysedOperand)
    {
        return this.GetCustomSignatureFormatting();
    }

    public string? CustomSignatureFormatting { get; init; }

    public IEnumerable<OperandTokenDescriptor> GetTokenDescriptors()
    {
        return this.MatchGroupsTokenMappings.SelectMany(t => t.Value.Values);
    }

    public IEnumerable<OperandTokenDescriptor> GetTokenDescriptors(AnalysedLine lineAnalysis,
        AnalysedOperand analysedOperand)
    {
        return this.GetTokenDescriptors();
    }

    private BasicOperandDescriptor(InstructionVariant mnemonic, OperandType type)
    {
        this.Type = type;
        this.Mnemonic = mnemonic;

        _regexes = null!;
        this.MatchGroupsTokenMappings = null!;

        this.CustomSignatureFormatting = type switch
        {
            OperandType.ImmediateOffset => "[ {0} {{, {1}}} ]",
            OperandType.ImmediatePreIndexed => "[ {0}, {1} ]!",
            OperandType.ImmediatePostIndexed => "[ {0} ], {1}",
            OperandType.RegisterOffset => "[ {0}, {{+/-}}{1}{{, {2} {3}}} ]",
            OperandType.RegisterPreIndexed => "[ {0}, {{+/-}}{1}{{, {2} {3}}} ]!",
            OperandType.RegisterPostIndexed => "[ {0} ], {{+/-}}{1}{{, {2} {3} }}",
            OperandType.RRX => "RRX",
            _ => this.CustomSignatureFormatting
        };
    }

    public BasicOperandDescriptor(InstructionVariant mnemonic, string literal) : this(mnemonic, OperandType.Literal)
    {
        this.Optional = false;
        this.MatchGroupsTokenMappings =
            ImmutableDictionary<int, ImmutableDictionary<int, OperandTokenDescriptor>>.Empty;
        _regexes = new List<Regex> { new("\\G" + literal, RegexOptions.Compiled) };
    }

    public BasicOperandDescriptor(InstructionVariant mnemonic, string regex, OperandType type, bool optional = false) :
        this(mnemonic, type)
    {
        this.Optional = optional;
        this.MatchGroupsTokenMappings =
            ImmutableDictionary<int, ImmutableDictionary<int, OperandTokenDescriptor>>.Empty;
        _regexes = new List<Regex> { new(regex, RegexOptions.Compiled) };
    }

    public BasicOperandDescriptor(InstructionVariant mnemonic, string regex, OperandType type,
        OperandTokenType tokenType,
        string tokenName, int singleTokenMatchGroup = 1, bool optional = false) : this(mnemonic, type)
    {
        this.Optional = optional;

        _singleToken = true;
        this.SingleTokenMatchGroup = singleTokenMatchGroup;

        this.MatchGroupsTokenMappings = ImmutableDictionary<int, ImmutableDictionary<int, OperandTokenDescriptor>>.Empty
            .Add(0, ImmutableDictionary<int, OperandTokenDescriptor>.Empty.Add(singleTokenMatchGroup,
                new OperandTokenDescriptor(tokenType, tokenName)));

        _regexes = new List<Regex> { new(regex, RegexOptions.Compiled) };
    }

    public BasicOperandDescriptor(InstructionVariant mnemonic, IEnumerable<string> matches, OperandType type,
        bool optional,
        params (int RegexIndex, int MatchGroup, OperandTokenDescriptor Token)[] tokens) : this(mnemonic, type)
    {
        this.Optional = optional;

        this.MatchGroupsTokenMappings = tokens.GroupBy(t => t.RegexIndex)
            .ToImmutableDictionary(g => g.Key,
                g => g.ToImmutableDictionary(a => a.MatchGroup,
                    a => a.Token));

        _regexes = matches.Select(m => new Regex(m, RegexOptions.Compiled)).ToList();
    }

    public BasicOperandDescriptor(InstructionVariant mnemonic, string regex, OperandType type, bool optional,
        params (int RegexIndex, int MatchGroup, OperandTokenDescriptor Token)[] tokens) : this(mnemonic,
        new[] { regex }, type,
        optional, tokens)
    {
    }

    public BasicOperandDescriptor(InstructionVariant mnemonic, IEnumerable<string> matches, OperandType type,
        bool optional,
        ImmutableDictionary<int, ImmutableDictionary<int, OperandTokenDescriptor>> tokenMappings) : this(mnemonic, type)
    {
        this.Optional = optional;

        this.MatchGroupsTokenMappings = tokenMappings;
        _regexes = matches.Select(m => new Regex(m, RegexOptions.Compiled)).ToList();
    }
}
