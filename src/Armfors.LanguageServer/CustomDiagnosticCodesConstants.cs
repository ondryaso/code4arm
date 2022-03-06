// CustomDiagnosticCodesConstants.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer;

public static class DiagnosticCodes
{
    public static readonly DiagnosticCode CannotSetFlags = new(1);
    public static readonly DiagnosticCode CannotBeConditional = new(2);
    public static readonly DiagnosticCode InvalidConditionCode = new(3);
    public static readonly DiagnosticCode InvalidSpecifier = new(4);
    public static readonly DiagnosticCode SpecifierNotAllowed = new(5);
    public static readonly DiagnosticCode InvalidMnemonic = new(6);
}
