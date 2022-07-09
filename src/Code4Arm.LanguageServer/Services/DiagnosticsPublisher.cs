// DiagnosticsPublisher.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using Code4Arm.LanguageServer.CodeAnalysis.Models;
using Code4Arm.LanguageServer.Extensions;
using Code4Arm.LanguageServer.Models;
using Code4Arm.LanguageServer.Services.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Server;
using OmniSharp.Extensions.LanguageServer.Server;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.Services;

public class DiagnosticsPublisher : IDiagnosticsPublisher
{
    private readonly ILanguageServerFacade _lsFacade;
    private readonly ISourceStore _sourceStore;
    private readonly ILanguageServerConfiguration _configuration;
    private readonly ILogger<DiagnosticsPublisher> _logger;

    public DiagnosticsPublisher(ILanguageServerFacade lsFacade, ISourceStore sourceStore,
        ILanguageServerConfiguration configuration,
        ILogger<DiagnosticsPublisher> logger)
    {
        _lsFacade = lsFacade;
        _sourceStore = sourceStore;
        _configuration = configuration;
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
        var suppressed = prepSource.SuppressedLines;
        foreach (var analysis in analyser.GetLineAnalyses())
        {
            // TODO: make more effective
            var originalRange = prepSource.GetOriginalRange(analysis.AnalysedRange);
            if (((List<int>)suppressed).Contains(originalRange.Start.Line))
                continue;

            // Labels
            foreach (var label in analysis.Labels)
            {
                if (label.Redefines != null && label.Range.Start.Line == analysis.LineIndex)
                {
                    diags.Add(new Diagnostic()
                    {
                        Code = -1,
                        Message =
                            $"Redefines symbol at line {prepSource.GetOriginalLine(label.Redefines.Range.Start.Line) + 1}.",
                        Range = prepSource.GetOriginalRange(label.Range),
                        Severity = label.Redefines.CanBeRedefined
                            ? DiagnosticSeverity.Hint
                            : DiagnosticSeverity.Error,
                        Source = Constants.ServiceSource
                    });
                }
            }

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
                            analysis.LineIndex, analysis.LineLength - 1);
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
                            : new Range(analysis.LineIndex, Math.Min(analysis.Operands!.Last().Range.End.Character + 1, analysis.LineLength - 1),
                                analysis.LineIndex, analysis.LineLength - 1);

                        diags.Add(new Diagnostic()
                        {
                            Code = DiagnosticCodes.OperandExpected,
                            Message = analysis.ErroneousOperandIndex == 0
                                ? "Operand expected."
                                : "Another operand expected.",
                            Range = prepSource.GetOriginalRange(range),
                            Severity = DiagnosticSeverity.Error,
                            Source = Constants.ServiceSource
                        });

                        break;
                    }

                    var erroneous = analysis.Operands![analysis.ErroneousOperandIndex];
                    if (erroneous.Result != OperandResult.InvalidTokens)
                    {
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
                }

                    break;
                case LineAnalysisState.Directive or LineAnalysisState.InvalidDirective:
                {
                    var directive = analysis.Directive;

                    if (directive == null) break;
                    if (directive.State == DirectiveState.Valid) break;

                    var (code, message) = GetDirectiveDiagnostic(directive);

                    diags.Add(new Diagnostic()
                    {
                        Code = code,
                        Message = message,
                        Range = prepSource.GetOriginalRange(directive.State == DirectiveState.UnknownDirective
                            ? directive.DirectiveRange
                            : directive.ParametersRange),
                        Severity = directive.Severity,
                        Source = Constants.ServiceSource
                    });

                    break;
                }
            }

            if (analysis.Operands is { Count: > 0 })
            {
                foreach (var token in analysis.Operands
                                              .Where(operand => operand.Tokens != null)
                                              .SelectMany(operand => operand.Tokens!
                                                                            .Where(t => t.Result !=
                                                                                OperandTokenResult.Valid)))
                {
                    var (code, message) = GetOperandTokenDiagnostic(token);

                    diags.Add(new Diagnostic()
                    {
                        Code = code,
                        Message = message,
                        Range = prepSource.GetOriginalRange(token.Range),
                        Severity = token.Severity,
                        Source = Constants.ServiceSource
                    });
                }
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

        var functions = analyser.GetFunctions().ToList();
        functions.Sort((a, b) => a.StartLine - b.StartLine);

        // Function endings
        for (var i = 0; i < functions.Count; i++)
        {
            var function = functions[i];

            if (function.TargetAnalysedLabel == null)
                continue;

            if (function.EndLine == -1)
            {
                diags.Add(new Diagnostic()
                {
                    Code = -1,
                    Message = $"No instruction that would end function '{function.Label}' found.",
                    Range = prepSource.GetOriginalRange(function.TargetAnalysedLabel.Range),
                    Severity = DiagnosticSeverity.Hint,
                    Source = Constants.ServiceSource
                });
            }

            if (i > 0 && function.StartLine <= functions[i - 1].EndLine)
            {
                diags.Add(new Diagnostic()
                {
                    Code = -1,
                    Message =
                        $"Function '{function.Label}' starts before function '{functions[i - 1].Label}' has ended.",
                    Range = prepSource.GetOriginalRange(function.TargetAnalysedLabel.Range),
                    Severity = DiagnosticSeverity.Hint,
                    Source = Constants.ServiceSource
                });
            }
        }

        if (!(await _configuration.GetServerOptions()).EnableErrors)
            diags.RemoveAll(d => d.Severity == DiagnosticSeverity.Error);

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
            OperandResult.UnexpectedOperand => (DiagnosticCodes.OperandUnexpected, "No operand can be used here."),
            OperandResult.SyntaxError => (DiagnosticCodes.OperandSyntaxError, "Syntax error in operand."),
            OperandResult.MissingOperand => (DiagnosticCodes.OperandExpected, "Another operand expected."),
            _ => (-1, string.Empty)
        };
    }

    private static (DiagnosticCode DiagnosticCode, string Message) GetOperandTokenDiagnostic(
        AnalysedOperandToken analysedOperandToken)
    {
        return analysedOperandToken.Result switch
        {
            OperandTokenResult.InvalidRegister => (-1, "Invalid register."), // TODO: say why
            OperandTokenResult.InvalidImmediateValue => (-1,
                "Immediate value (integer constant) is out of bounds for this operand."),
            OperandTokenResult.InvalidImmediateConstantValue => (-1,
                "This immediate value cannot be encoded. Only number that can be expressed as a 8-bit number rotated by even rotation number can be used."), // TODO: say why
            OperandTokenResult.ImmediateConstantNegative => (-1,
                "A negative immediate constant will be encoded as the reverse instruction (ADD for SUB and vice-versa). This may not be what you intended."),
            OperandTokenResult.InvalidShiftType => (-1, "Invalid shift type."), // TODO: list possible shift types
            OperandTokenResult.InvalidRegisterListEntry => (-1,
                "This register cannot be used in this register list."), // TODO: say why
            OperandTokenResult.RegisterListMustContainPc => (-1,
                "The register list must contain the program counter (PC/R15)."),
            OperandTokenResult.RegisterListCannotContainPc => (-1,
                "The register list cannot contain the program counter (PC/R15)."),
            OperandTokenResult.InvalidAlignment => (-1,
                "Invalid alignment value."), // TODO: list possible alignment values
            OperandTokenResult.InvalidSpecialOperand => (DiagnosticCodes.OperandSyntaxError, "Invalid operand."),
            OperandTokenResult.UndefinedLabel => (-1, "Undefined label."),
            OperandTokenResult.SyntaxError => (DiagnosticCodes.OperandSyntaxError, "Invalid operand token."),
            _ => (-1, string.Empty)
        };
    }

    private static (DiagnosticCode DiagnosticCode, string Message) GetDirectiveDiagnostic(
        AnalysedDirective analysedDirective)
    {
        // TODO
        return analysedDirective.State switch
        {
            DirectiveState.Valid => (-1, ""),
            DirectiveState.UnknownDirective => (10, "Unknown directive."),
            DirectiveState.InvalidDirectiveSyntax => (DiagnosticCodes.GenericSyntaxError, "Invalid directive syntax."),
            DirectiveState.UnknownType => (-1, ""),
            DirectiveState.InvalidConstant => (-1, "Invalid constant."),
            DirectiveState.NopDirective => (-1, ""),
            DirectiveState.InvalidArch => (-1, ""),
            DirectiveState.InvalidArchExtension => (-1, ""),
            DirectiveState.InvalidFloatFormat => (-1, ""),
            DirectiveState.ThumbUnsupported => (-1, ""),
            DirectiveState.DividedSyntaxUnsupported => (-1, ""),
            DirectiveState.UnquotedString => (-1, ""),
            _ => (-1, string.Empty)
        };
    }
}
