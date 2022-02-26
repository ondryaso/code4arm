// AnalysedLine.cs
// Author: Ondřej Ondryáš

namespace Armfors.LanguageServer.CodeAnalysis.Models;

public enum LineAnalysisState
{
    Empty, // line empty, initial state
    InvalidMnemonic, // no instruction matching the current text of the line
    HasMatches, // there are one or more candidate mnemonics for the current text of the line
    HasFullMatch, // the current text of the line corresponds to a mnemonic (there may be other matches)
    ValidLine, // the line is terminated with valid contents
    SetFlagsFlagLoaded, // there's a full match and the -S variant is used
    PossibleConditionCode, // there's a full match and the user is possibly typing a condition code
    ConditionCodeLoaded, // there's a full match and a condition code has been typed 
    LoadingQualifierOrVectorDataType, // a mnemonic (incl. S or CC) has been recognised and the user typed a dot indicating either .W/.N or a vector data type
    QualifierLoaded, // a .W/.N qualifier has been loaded, now only a vector data type specifier or a space/newline may follow
    InvalidQualifierOrVectorDataType, // the text after a dot is not W/N (nor is it a vector data type)
    NotVectorInstruction, // the mnemonic doesn't allow specifying vector data types
    LoadingVectorDataType, // a qualifier was used and the user has typed another dot
    VectorDataTypeLoaded, // a vector data type has been loaded (a qualifier may not be used now)
    InvalidVectorDataType, // the string is not a valid vector data type
    MnemonicLoaded, // a whole, valid mnemonic (including flags) has been loaded
    OperandAnalysis, // operands are being accepted
    InvalidOperands // the user is typing operands on a line with an instruction with no operands or they have ended the line when there should have been operands
}

public class AnalysedLine
{
    public int Line { get; private set; }

    /// <summary>
    /// The instruction doesn't allow the used vector data type.
    /// </summary>
    public bool UnsupportedVectorDataType { get; private set; }

    /// <summary>
    /// No mnemonic matches the line's text.
    /// </summary>
    public bool NoMatchingMnemonic { get; private set; }

    /// <summary>
    /// Mnemonics matching the current line's text.
    /// </summary>
    public IEnumerable<string> MatchingMnemonics { get; }

    /// <summary>
    /// The recognised mnemonic.
    /// </summary>
    public string? Mnemonic { get; private set; }

    /// <summary>
    /// A valid mnemonic has been recognised.
    /// </summary>
    public bool MnemonicRecognised => this.Mnemonic != null;

    /// <summary>
    /// The line contains a valid mnemonic (including flags).
    /// </summary>
    public bool MnemonicFinished { get; private set; }

    /// <summary>
    /// The line contains a valid instruction (including operands).
    /// </summary>
    public bool Finished { get; private set; }

    /// <summary>
    /// The mnemonic describes the -S variant of an instruction that sets flags.
    /// </summary>
    public bool SetsFlags { get; private set; }

    /// <summary>
    /// The instruction's condition code.
    /// </summary>
    public string? ConditionCode { get; private set; }

    /// <summary>
    /// The mnemonic describes a conditionally executed instruction.
    /// </summary>
    public bool IsConditional => this.ConditionCode != null;

    /// <summary>
    /// A condition code has been provided but this instruction does not support it.
    /// </summary>
    public bool CannotBeConditional { get; private set; }

    /// <summary>
    /// An S-suffixed variant of a mnemonic has been used but the instruction does not support settings flags.
    /// </summary>
    public bool CannotSetFlags { get; private set; }

    /// <summary>
    /// Operands were used but the instruction does not support them.
    /// </summary>
    public bool NoOperandsAllowed { get; private set; }

    /// <summary>
    /// Operands are required and they are missing.
    /// </summary>
    public bool MissingOperands { get; private set; }
}
