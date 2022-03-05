namespace Armfors.LanguageServer.CodeAnalysis.Models;

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

public class AnalysedSpecifier
{
    public bool IsInstructionSizeQualifier { get; }
    public bool IsVectorDataType { get; }

    public bool IsComplete { get; }
    public int VectorDataTypeIndex { get; } = -1;

    /// <summary>
    /// Determines whether this specifier is allowed at its position.
    /// </summary>
    public bool AllowedHere { get; }

    /// <summary>
    /// Determines the position of this specifier in the source text.
    /// </summary>
    public Range Range { get; }

    public VectorDataType VectorDataType { get; } = VectorDataType.Unknown;
    public InstructionSize InstructionSize { get; } = (InstructionSize)(-1);

    /// <summary>
    /// The actual textual representation of this specifier.
    /// </summary>
    public string Text { get; }

    public AnalysedSpecifier(string text, Range range, VectorDataType vectorDataType, int vectorDataTypeIndex,
        bool allowedHere = true)
    {
        this.AllowedHere = allowedHere;
        this.VectorDataTypeIndex = vectorDataTypeIndex;
        this.IsVectorDataType = true;
        this.VectorDataType = vectorDataType;
        this.Text = text;
        this.Range = range;
    }

    public AnalysedSpecifier(string text, Range range, InstructionSize instructionSize, bool allowedHere = true)
    {
        this.AllowedHere = allowedHere;
        this.IsInstructionSizeQualifier = true;
        this.InstructionSize = instructionSize;
        this.Text = text;
        this.Range = range;
    }

    public AnalysedSpecifier(string text, Range range)
    {
        this.Text = text;
        this.Range = range;
        this.AllowedHere = false;
        this.IsComplete = false;
    }
}

public class AnalysedLine
{
    public int StartLine
    {
        get => this.Range.Start.Line;
        set => this.Range.Start.Line = value;
    }

    public int EndLine
    {
        get => this.Range.End.Line;
        set => this.Range.End.Line = value;
    }

    public int StartCharacter
    {
        get => this.Range.Start.Character;
        set => this.Range.Start.Character = value;
    }

    public int EndCharacter
    {
        get => this.Range.End.Character;
        set => this.Range.End.Character = value;
    }

    public Range Range { get; }
    public bool IsWhitespace { get; internal set; }

    /// <summary>
    /// Initializes the line with a range.
    /// </summary>
    internal AnalysedLine(int line, int startCharacter, int endCharacter, LineAnalysisState state)
    {
        this.Range = new Range(line, startCharacter, line, endCharacter);
        this.State = state;
    }

    internal AnalysedLine(int line)
    {
        this.Range = new Range(line, 0, line, 0);
    }

    /// <summary>
    /// The current analysis state of this line.
    /// </summary>
    public LineAnalysisState State { get; internal set; }

    /// <summary>
    /// Mnemonics matching the current line's text.
    /// </summary>
    public List<InstructionVariant> MatchingMnemonics { get; internal set; } = new();

    /// <summary>
    /// No mnemonic matches the line's text.
    /// </summary>
    public bool NoMatchingMnemonic => this.MatchingMnemonics.Count == 0;

    /// <summary>
    /// The recognised mnemonic (a full match).
    /// </summary>
    public InstructionVariant? Mnemonic { get; internal set; }

    /// <summary>
    /// A valid mnemonic has been recognised (<see cref="Mnemonic"/> is not null).
    /// </summary>
    public bool HasMnemonicMatch => this.Mnemonic != null;

    /// <summary>
    /// The line contains a mnemonic terminated with a whitespace.
    /// Flags have been read (or there isn't any).
    /// </summary>
    public bool MnemonicFinished { get; internal set; }

    /// <summary>
    /// The mnemonic describes the -S variant of an instruction that sets flags.
    /// </summary>
    public bool SetsFlags { get; internal set; }

    /// <summary>
    /// The instruction's condition code.
    /// </summary>
    public ConditionCode? ConditionCode { get; internal set; }

    public bool HasUnterminatedConditionCode { get; internal set; }
    public bool HasInvalidConditionCode { get; internal set; }

    /// <summary>
    /// The mnemonic describes a conditionally executed instruction (with valid loaded condition code).
    /// </summary>
    /// <remarks>
    /// This is equal to <see cref="ConditionCode"/> having a value.
    /// </remarks>
    public bool IsConditional => this.ConditionCode != null;

    /// <summary>
    /// The mnemonic contains a condition code (either valid or invalid).
    /// </summary>
    /// <remarks>
    /// This is equal to <see cref="ConditionCodeRange"/> having a value, or to one of <see cref="IsConditional"/>,
    /// <see cref="HasInvalidConditionCode"/>, <see cref="HasUnterminatedConditionCode"/> or <see cref="CannotBeConditional"/> being true.
    /// </remarks>
    /// <example>
    /// Suppose there's an unconditional instruction 'ABC' and a possibly conditional 'XYZ'.
    /// This would be true for: XYZEQ, XYZE, XYZEX, ABCEQ, ABCEQ, ABCE, ABCEX.
    /// </example>
    public bool HasConditionCodePart => this.ConditionCodeRange != null;

    /// <summary>
    /// A condition code has been provided but this instruction does not support it.
    /// </summary>
    public bool CannotBeConditional { get; internal set; }

    /// <summary>
    /// An S-suffixed variant of a mnemonic has been used but the instruction does not support settings flags.
    /// </summary>
    public bool CannotSetFlags { get; internal set; }

    /// <summary>
    /// Operands were used but the instruction does not support them.
    /// </summary>
    public bool NoOperandsAllowed { get; internal set; }

    /// <summary>
    /// Operands are required and they are missing.
    /// </summary>
    public bool MissingOperands { get; internal set; }

    public Range? MnemonicRange { get; internal set; }
    public Range? SetFlagsRange { get; internal set; }
    public Range? ConditionCodeRange { get; internal set; }

    public List<Range>? OperandRanges { get; internal set; }

    public List<AnalysedSpecifier> Specifiers { get; internal set; } = new();
}
