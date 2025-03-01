// CustomDiagnosticCodesConstants.cs
// Author: Ondřej Ondryáš

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
