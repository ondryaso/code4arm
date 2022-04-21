using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

public enum AnalysedTokenType
{
    Whitespace,
    Mnemonic,
    SetFlagsFlag,
    ConditionCode,
    Specifier,
    Operand,
    OperandToken,
    Label,
    Directive,
    DirectiveParameters
}

public class AnalysedTokenLookupResult
{
    public Range TokenRange { get; } = null!;
    public AnalysedTokenType Type { get; }

    private AnalysedTokenLookupResult(AnalysedLine line)
    {
        this.AnalysedLine = line;
    }

    /// <summary>
    /// Constructs a <see cref="AnalysedTokenType.Whitespace"/> result for a given line.
    /// The <see cref="TokenRange"/> is manually set using the <paramref name="range"/> parameter and should contain
    /// the single character long range of the whitespace.
    /// </summary>
    /// <param name="line">The line.</param>
    /// <param name="range">The range of the whitespace.</param>
    internal AnalysedTokenLookupResult(AnalysedLine line, Range range)
        : this(line)
    {
        this.Type = AnalysedTokenType.Whitespace;
        this.TokenRange = range;
    }

    /// <summary>
    /// Constructs a <see cref="AnalysedTokenType.Mnemonic"/>, <see cref="AnalysedTokenType.SetFlagsFlag"/>
    /// or <see cref="ConditionCode"/> result for a given line. The corresponding data is extracted from the line.
    /// </summary>
    /// <param name="line">The line analysis object.</param>
    /// <param name="type"><see cref="AnalysedTokenType.Mnemonic"/>, <see cref="AnalysedTokenType.SetFlagsFlag"/>
    /// or <see cref="ConditionCode"/>.</param>
    /// <exception cref="InvalidOperationException"><paramref name="type"/> is not one of the supported values.</exception>
    internal AnalysedTokenLookupResult(AnalysedLine line, AnalysedTokenType type)
        : this(line)
    {
        switch (type)
        {
            case AnalysedTokenType.Mnemonic:
                this.Type = AnalysedTokenType.Mnemonic;
                this.Mnemonic = line.Mnemonic!;
                this.TokenRange = line.MnemonicRange!;
                break;
            case AnalysedTokenType.SetFlagsFlag:
                this.Type = AnalysedTokenType.SetFlagsFlag;
                this.Mnemonic = line.Mnemonic!;
                this.TokenRange = line.SetFlagsRange!;
                break;
            case AnalysedTokenType.ConditionCode:
                this.Type = AnalysedTokenType.ConditionCode;
                this.Mnemonic = line.Mnemonic!;
                this.ConditionCode = line.ConditionCode;
                this.TokenRange = line.ConditionCodeRange!;
                break;
            default:
                throw new InvalidOperationException();
        }
    }

    internal AnalysedTokenLookupResult(AnalysedLine line, AnalysedSpecifier specifier)
        : this(line)
    {
        this.Type = AnalysedTokenType.Specifier;
        this.TokenRange = specifier.Range;
        this.Specifier = specifier;
    }

    internal AnalysedTokenLookupResult(AnalysedLine line, AnalysedOperand operand)
        : this(line)
    {
        this.Type = AnalysedTokenType.Operand;
        this.TokenRange = operand.Range;
        this.Operand = operand;
    }

    internal AnalysedTokenLookupResult(AnalysedLine line, AnalysedLabel label)
        : this(line)
    {
        this.Type = AnalysedTokenType.Label;
        this.TokenRange = label.Range;
        this.Label = label;
    }

    internal AnalysedTokenLookupResult(AnalysedLine line, AnalysedOperand operand, AnalysedOperandToken operandToken)
        : this(line)
    {
        this.Type = AnalysedTokenType.OperandToken;
        this.TokenRange = operandToken.Range;
        this.Operand = operand;
        this.OperandToken = operandToken;
    }

    internal AnalysedTokenLookupResult(AnalysedLine line, AnalysedDirective directive, bool parametersPart)
        : this(line)
    {
        this.Type = parametersPart ? AnalysedTokenType.DirectiveParameters : AnalysedTokenType.Directive;
        this.TokenRange = parametersPart ? directive.DirectiveRange : directive.ParametersRange;
        this.Directive = directive;
    }

    public AnalysedLine AnalysedLine { get; }
    public InstructionVariant? Mnemonic { get; }
    public ConditionCode? ConditionCode { get; }
    public AnalysedSpecifier? Specifier { get; }
    public AnalysedOperand? Operand { get; }
    public AnalysedOperandToken? OperandToken { get; }
    public AnalysedDirective? Directive { get; }
    public AnalysedLabel? Label { get; }
}