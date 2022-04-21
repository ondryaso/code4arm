// LineAnalysisState.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

public enum LineAnalysisState
{
    Empty, // line empty, initial state
    Blank, // blank line (happens when the line only contains labels)
    Directive, // the line contains a valid directive
    InvalidDirective, // the line contains an invalid directive
    InvalidMnemonic, // no instruction matching the current text of the line
    HasMatches, // there are one or more candidate mnemonics for the current text of the line (but there's not a single valid mnemonic)
    HasFullMatch, // the current text of the line corresponds to a mnemonic (there may be other matches)
    ValidLine, // the line is terminated with valid contents
    PossibleConditionCode, // there's a full match and the user is possibly typing a condition code
    LoadingSpecifier, // a mnemonic (incl. S or CC) has been recognised and the user typed a dot indicating either .W/.N or a vector data type
    SpecifierSyntaxError, // the last specifier is not valid
    InvalidSpecifier, // the last specifier cannot be used here
    MnemonicLoaded, // a whole, valid mnemonic (including flags) has been loaded and a whitespace follows
    OperandAnalysis, // operands are being accepted
    InvalidOperands, // the user is typing operands on a line with an instruction with no operands or they have ended the line when there should have been operands
    SyntaxError // unexpected character loaded
}
