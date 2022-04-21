using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

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
        this.IsComplete = true;
    }

    public AnalysedSpecifier(string text, Range range, InstructionSize instructionSize, bool allowedHere = true)
    {
        this.AllowedHere = allowedHere;
        this.IsInstructionSizeQualifier = true;
        this.InstructionSize = instructionSize;
        this.Text = text;
        this.Range = range;
        this.IsComplete = true;
    }

    public AnalysedSpecifier(string text, Range range)
    {
        this.Text = text;
        this.Range = range;
        this.AllowedHere = false;
        this.IsComplete = false;
    }
}