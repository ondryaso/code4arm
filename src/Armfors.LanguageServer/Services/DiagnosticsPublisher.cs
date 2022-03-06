// DiagnosticsPublisher.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Server;

namespace Armfors.LanguageServer.Services;

public class DiagnosticsPublisher : IDiagnosticsPublisher
{
    private readonly ILanguageServerFacade _lsFacade;

    public DiagnosticsPublisher(ILanguageServerFacade lsFacade)
    {
        _lsFacade = lsFacade;
    }

    public async Task PublishAnalysisResult(ISourceAnalyser analyser, DocumentUri documentUri, int? documentVersion)
    {
        if (!_lsFacade.ClientSettings.Capabilities?.TextDocument?.PublishDiagnostics.IsSupported ?? false)
        {
            return;
        }

        var diags = new List<Diagnostic>();

        foreach (var analysis in analyser.GetLineAnalyses())
        {
            switch (analysis.State)
            {
                case LineAnalysisState.InvalidMnemonic:
                    diags.Add(new Diagnostic()
                    {
                        Code = DiagnosticCodes.InvalidMnemonic,
                        Message = $"Invalid instruction mnemonic.",
                        Range = analysis.AnalysedRange,
                        Severity = DiagnosticSeverity.Error,
                        Source = Constants.ServiceSource
                    });
                    break;
                case LineAnalysisState.SpecifierSyntaxError:
                    break;
                case LineAnalysisState.InvalidSpecifier:
                    break;
                case LineAnalysisState.InvalidOperands:
                    break;
                case LineAnalysisState.SyntaxError:
                    break;
            }

            // Set Flags
            if (analysis.CannotSetFlags)
            {
                diags.Add(new Diagnostic()
                {
                    Code = DiagnosticCodes.CannotSetFlags,
                    Message = $"Instruction {analysis.Mnemonic!.Mnemonic} cannot set flags.",
                    Range = analysis.AnalysedRange,
                    Severity = DiagnosticSeverity.Error,
                    Source = Constants.ServiceSource
                });
            }

            // Condition Codes
            if (analysis.CannotBeConditional)
            {
                diags.Add(new Diagnostic()
                {
                    Code = DiagnosticCodes.CannotBeConditional,
                    Message = $"Instruction {analysis.Mnemonic!.Mnemonic} cannot be conditional.",
                    Range = analysis.ConditionCodeRange!,
                    Severity = DiagnosticSeverity.Error,
                    Source = Constants.ServiceSource
                });
            }

            if (analysis.HasInvalidConditionCode || analysis.HasUnterminatedConditionCode)
            {
                diags.Add(new Diagnostic()
                {
                    Code = DiagnosticCodes.InvalidConditionCode,
                    Message = $"Invalid condition code.",
                    Range = analysis.ConditionCodeRange!,
                    Severity = DiagnosticSeverity.Error,
                    Source = Constants.ServiceSource
                });
            }

            // Specifiers
            foreach (var specifier in analysis.Specifiers)
            {
                if (!specifier.IsComplete)
                {
                    diags.Add(new Diagnostic()
                    {
                        Code = DiagnosticCodes.InvalidSpecifier,
                        Message = "Invalid specifier.",
                        Range = specifier.Range,
                        Severity = DiagnosticSeverity.Error,
                        Source = Constants.ServiceSource
                    });
                }
                else if (!specifier.AllowedHere)
                {
                    diags.Add(new Diagnostic()
                    {
                        Code = DiagnosticCodes.SpecifierNotAllowed,
                        Message = $"Specifier {specifier.Text} cannot be used here.",
                        Range = specifier.Range,
                        Severity = DiagnosticSeverity.Error,
                        Source = Constants.ServiceSource
                    });
                }
            }
        }

        var par = new PublishDiagnosticsParams()
        {
            Uri = documentUri,
            Version = documentVersion,
            Diagnostics = diags
        };

        _lsFacade.TextDocument.PublishDiagnostics(par);
    }
}
