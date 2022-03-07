// DiagnosticsPublisher.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Services.Abstractions;
using Microsoft.Extensions.Logging;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Server;

namespace Armfors.LanguageServer.Services;

public class DiagnosticsPublisher : IDiagnosticsPublisher
{
    private readonly ILanguageServerFacade _lsFacade;
    private readonly ISourceStore _sourceStore;
    private readonly ILogger<DiagnosticsPublisher> _logger;

    public DiagnosticsPublisher(ILanguageServerFacade lsFacade, ISourceStore sourceStore,
        ILogger<DiagnosticsPublisher> logger)
    {
        _lsFacade = lsFacade;
        _sourceStore = sourceStore;
        _logger = logger;
    }

    public async Task PublishAnalysisResult(ISourceAnalyser analyser, DocumentUri documentUri, int? documentVersion)
    {
        if (!_lsFacade.ClientSettings.Capabilities?.TextDocument?.PublishDiagnostics.IsSupported ?? false)
        {
            _logger.LogTrace("Diagnostics aren't published because the client doesn't support them.");
            return;
        }

        _logger.LogDebug("Publishing diagnostics.");
        var prepSource = await _sourceStore.GetPreprocessedDocument(documentUri);
        // TODO: prepSource check?

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
                        Range = prepSource.GetOriginalRange(analysis.AnalysedRange),
                        Severity = DiagnosticSeverity.Error,
                        Source = Constants.ServiceSource
                    });
                    break;
                case LineAnalysisState.SyntaxError:
                    diags.Add(new Diagnostic()
                    {
                        Code = DiagnosticCodes.GenericSyntaxError,
                        Message = $"Syntax error.",
                        Range = prepSource.GetOriginalRange(analysis.AnalysedRange),
                        Severity = DiagnosticSeverity.Error,
                        Source = Constants.ServiceSource
                    });
                    break;
                case LineAnalysisState.InvalidOperands:
                    break;
            }

            // Set Flags
            if (analysis.CannotSetFlags)
            {
                diags.Add(new Diagnostic()
                {
                    Code = DiagnosticCodes.CannotSetFlags,
                    Message = $"Instruction {analysis.Mnemonic!.Mnemonic} cannot set flags.",
                    Range = prepSource.GetOriginalRange(analysis.AnalysedRange),
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
                    Range = prepSource.GetOriginalRange(analysis.ConditionCodeRange!),
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
                    Range = prepSource.GetOriginalRange(analysis.ConditionCodeRange!),
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
                        Range = prepSource.GetOriginalRange(specifier.Range),
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
                        Range = prepSource.GetOriginalRange(specifier.Range),
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
