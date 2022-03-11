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
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

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
                        Message = "Invalid instruction mnemonic.",
                        Range = prepSource.GetOriginalRange(analysis.AnalysedRange),
                        Severity = DiagnosticSeverity.Error,
                        Source = Constants.ServiceSource
                    });
                    break;
                case LineAnalysisState.SyntaxError:
                    diags.Add(new Diagnostic()
                    {
                        Code = DiagnosticCodes.GenericSyntaxError,
                        Message = "Syntax error.",
                        Range = prepSource.GetOriginalRange(analysis.AnalysedRange),
                        Severity = DiagnosticSeverity.Error,
                        Source = Constants.ServiceSource
                    });
                    break;
                case LineAnalysisState.InvalidOperands:
                {
                    if (analysis.NoOperandsAllowed)
                    {
                        var range = new Range(analysis.LineIndex, analysis.MnemonicRange!.End.Character + 1,
                            analysis.LineIndex, analysis.LineLength);
                        diags.Add(new Diagnostic()
                        {
                            Code = DiagnosticCodes.NoOperandsAllowed,
                            Message = "Instruction doesn't have any operands.",
                            Range = prepSource.GetOriginalRange(range),
                            Severity = DiagnosticSeverity.Error,
                            Source = Constants.ServiceSource
                        });
                        break;
                    }

                    if (analysis.MissingOperands)
                    {
                        var range = analysis.ErroneousOperandIndex == 0
                            ? analysis.MnemonicRange!
                            : new Range(analysis.LineIndex, analysis.Operands!.Last().Range.End.Character + 1,
                                analysis.LineIndex, analysis.LineLength);

                        diags.Add(new Diagnostic()
                        {
                            Code = DiagnosticCodes.OperandExpected,
                            Message = analysis.ErroneousOperandIndex == 0 ? "Operand expected." : "Another operand expected.",
                            Range = prepSource.GetOriginalRange(range),
                            Severity = DiagnosticSeverity.Error,
                            Source = Constants.ServiceSource
                        });
                        break;
                    }

                    var erroneous = analysis.Operands![analysis.ErroneousOperandIndex];
                    var (code, message) = GetOperandDiagnostic(erroneous);

                    diags.Add(new Diagnostic()
                    {
                        Code = code,
                        Message = message,
                        Range = prepSource.GetOriginalRange(erroneous.ErrorRange!),
                        Severity = DiagnosticSeverity.Error,
                        Source = Constants.ServiceSource
                    });
                }
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
                    if (specifier.IsVectorDataType && !analysis.Mnemonic!.IsVector)
                    {
                        diags.Add(new Diagnostic()
                        {
                            Code = DiagnosticCodes.SpecifierNotAllowed,
                            Message =
                                $"{analysis.Mnemonic.Mnemonic} is not a SIMD/FP instruction, data type specifier {specifier.Text} cannot be used here.",
                            Range = prepSource.GetOriginalRange(specifier.Range),
                            Severity = DiagnosticSeverity.Error,
                            Source = Constants.ServiceSource
                        });
                    }
                    else if (specifier.IsVectorDataType)
                    {
                        diags.Add(new Diagnostic()
                        {
                            Code = DiagnosticCodes.SpecifierNotAllowed,
                            Message = $"Data type specifier {specifier.Text} cannot be used here.",
                            Range = prepSource.GetOriginalRange(specifier.Range),
                            Severity = DiagnosticSeverity.Error,
                            Source = Constants.ServiceSource
                        });
                    }
                    else
                    {
                        diags.Add(new Diagnostic()
                        {
                            Code = DiagnosticCodes.SpecifierNotAllowed,
                            Message =
                                "An instruction encoding size specifier must come right after the instruction mnemonic.",
                            Range = prepSource.GetOriginalRange(specifier.Range),
                            Severity = DiagnosticSeverity.Error,
                            Source = Constants.ServiceSource
                        });
                    }
                }
                else if (specifier.IsInstructionSizeQualifier)
                {
                    diags.Add(new Diagnostic()
                    {
                        Code = DiagnosticCodes.InstructionSizeNotSupported,
                        Message =
                            "An instruction encoding size specifier (.W/.N) is not supported in A32 mode and will lead to errors when assembling.",
                        Range = prepSource.GetOriginalRange(specifier.Range),
                        Severity = DiagnosticSeverity.Warning,
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

    private static (DiagnosticCode DiagnosticCode, string Message) GetOperandDiagnostic(AnalysedOperand analysedOperand)
    {
        return analysedOperand.Result switch
        {
            OperandResult.InvalidRegister => (-1, "Invalid register."), // TODO: say why
            OperandResult.InvalidImmediateValue => (-1, "Invalid immediate value."), // TODO: say why
            OperandResult.InvalidShiftType => (-1, "Invalid shift type."), // TODO: list possible shift types
            OperandResult.InvalidRegisterList => (-1, "Invalid register list."), // TODO: say why
            OperandResult.RegisterListMustContainPc => (-1,
                "The register list must contain the program counter (PC/R15)."),
            OperandResult.RegisterListCannotContainPc => (-1,
                "The register list cannot contain the program counter (PC/R15)."),
            OperandResult.InvalidAlignment => (-1, "Invalid alignment value."), // TODO: list possible alignment values
            OperandResult.InvalidSpecialOperand => (DiagnosticCodes.OperandSyntaxError, "Invalid operand."),
            OperandResult.UnexpectedOperand => (DiagnosticCodes.OperandUnexpected, "No operand can be used here."),
            OperandResult.SyntaxError => (DiagnosticCodes.OperandSyntaxError, "Invalid operand."),
            OperandResult.Valid => (-1, string.Empty), // Doesn't happen
            _ => (-1, string.Empty)
        };
    }
}
