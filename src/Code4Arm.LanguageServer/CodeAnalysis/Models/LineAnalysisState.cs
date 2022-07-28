// LineAnalysisState.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

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
