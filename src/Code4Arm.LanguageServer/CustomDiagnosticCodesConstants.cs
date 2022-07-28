// CustomDiagnosticCodesConstants.cs
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

using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer;

public static class DiagnosticCodes
{
    public static readonly DiagnosticCode CannotSetFlags = new(1);
    public static readonly DiagnosticCode CannotBeConditional = new(2);
    public static readonly DiagnosticCode InvalidConditionCode = new(3);
    public static readonly DiagnosticCode InvalidSpecifier = new(4);
    public static readonly DiagnosticCode SpecifierNotAllowed = new(5);
    public static readonly DiagnosticCode InvalidMnemonic = new(5);
    public static readonly DiagnosticCode GenericSyntaxError = new(6);
    public static readonly DiagnosticCode InstructionSizeNotSupported = new(7);
    public static readonly DiagnosticCode NoOperandsAllowed = new(8);
    public static readonly DiagnosticCode OperandExpected = new(9);
    public static readonly DiagnosticCode OperandSyntaxError = new(10);
    public static readonly DiagnosticCode OperandUnexpected = new(11);
}
