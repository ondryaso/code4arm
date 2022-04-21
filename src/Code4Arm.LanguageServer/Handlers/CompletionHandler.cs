// CompletionHandler.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.Extensions;
using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using Code4Arm.LanguageServer.CodeAnalysis.Models;
using Code4Arm.LanguageServer.Models.Abstractions;
using Code4Arm.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Server;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.Handlers;

public class CompletionHandler : CompletionHandlerBase
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;
    private readonly IInstructionProvider _instructionProvider;
    private readonly ILocalizationService _loc;
    private readonly IInstructionDocumentationProvider _instrDoc;
    private readonly IInstructionValidatorProvider _instructionValidatorProvider;
    private readonly ISymbolDocumentationProvider _symbolDoc;
    private readonly ILanguageServerConfiguration _configurationContainer;

    public CompletionHandler(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore,
        IInstructionProvider instructionProvider, ILocalizationService localizationService,
        IInstructionDocumentationProvider instructionDocumentationProvider,
        IInstructionValidatorProvider instructionValidatorProvider,
        ISymbolDocumentationProvider symbolDocumentationProvider, ILanguageServerConfiguration configurationContainer)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
        _instructionProvider = instructionProvider;
        _loc = localizationService;
        _instrDoc = instructionDocumentationProvider;
        _instructionValidatorProvider = instructionValidatorProvider;
        _symbolDoc = symbolDocumentationProvider;
        _configurationContainer = configurationContainer;
    }

    public override async Task<CompletionList> Handle(CompletionParams request, CancellationToken cancellationToken)
    {
        var source = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri);
        var analyser = _sourceAnalyserStore.GetAnalyser(source);
        var prepPosition = source.GetPreprocessedPosition(request.Position);

        await analyser.TriggerLineAnalysis(prepPosition.Line, false);

        var lineAnalysis = analyser.GetLineAnalysis(prepPosition.Line);
        if (lineAnalysis == null)
        {
            return new CompletionList(false);
        }

        var config = await _configurationContainer.GetServerOptions(request);

        // Kdy ukázat nápovědu instrukcí?
        // Automaticky při psaní instrukce – PODLE STAVU ANALÝZY:
        // - HasMatches: píšu instrukci, napovídám pouze mnemoniky
        // - HasFullMatch:
        //   1) -S variantu
        //   2) HasUnterminatedConditionCode -> ukázat i možné CC
        //   3) další instrukce z MatchingMnemonics
        // Po ručním triggeru – PODLE POZICE KURZORU

        var ret = new List<CompletionItem>();

        // CC/S completions
        if (lineAnalysis.PreFinishState == LineAnalysisState.HasFullMatch && lineAnalysis.Specifiers.Count == 0)
        {
            if (!lineAnalysis.SetsFlags && lineAnalysis.Mnemonic!.HasSetFlagsVariant &&
                lineAnalysis.ConditionCodeRange == null)
            {
                var originalRangeForSetFlags = source.GetOriginalRange(new Range(lineAnalysis.LineIndex,
                    prepPosition.Character, lineAnalysis.LineIndex, prepPosition.Character));

                ret.Add(new CompletionItem()
                {
                    Kind = CompletionItemKind.Event,
                    Label = _loc["Set flags", ILocalizationService.CompletionLabelTag],
                    Detail = _loc["Set flags", ILocalizationService.CompletionDescriptionTag],
                    Documentation = _symbolDoc["Set flags"],
                    FilterText = "S",
                    TextEdit = new TextEdit()
                    {
                        Range = originalRangeForSetFlags,
                        NewText = "S"
                    },
                    SortText = "10S"
                });
            }

            if ((lineAnalysis.HasUnterminatedConditionCode || lineAnalysis.HasInvalidConditionCode)
                && lineAnalysis.Mnemonic!.CanBeConditional && lineAnalysis.ConditionCodeRange != null)
            {
                var ccPart = await source.GetTextAsync(lineAnalysis.ConditionCodeRange with
                {
                    End = new Position(lineAnalysis.LineIndex, lineAnalysis.ConditionCodeRange.End.Character - 1)
                });

                var ccValues = Enum.GetValues<ConditionCode>()
                    .Where(n => n.ToString().StartsWith(ccPart.ToUpperInvariant()));

                foreach (var ccValue in ccValues)
                {
                    var completionItem = this.MakeCompletionItemForConditionCode(lineAnalysis, ccValue, source);
                    ret.Add(completionItem);
                }
            }
            else if (lineAnalysis.Mnemonic!.CanBeConditional && lineAnalysis.ConditionCodeRange == null)
            {
                var ccValues = Enum.GetValues<ConditionCode>();
                var range = lineAnalysis.AnalysedRange.Trail(2);

                foreach (var ccValue in ccValues)
                {
                    if (ccValue == ConditionCode.Invalid)
                        continue;

                    var completionItem = this.MakeCompletionItemForConditionCode(lineAnalysis, ccValue, source, range);
                    ret.Add(completionItem);
                }
            }
        }

        // Vector data types completions
        if (lineAnalysis.PreFinishState is LineAnalysisState.HasFullMatch or LineAnalysisState.LoadingSpecifier &&
            lineAnalysis.Mnemonic!.IsVector)
        {
            var currentSpecifierIndex = lineAnalysis.Specifiers.Count;
            if (lineAnalysis.Specifiers.FirstOrDefault()?.IsInstructionSizeQualifier ?? false)
                currentSpecifierIndex--;

            var lastSpec = lineAnalysis.Specifiers.LastOrDefault();
            int startIndex;

            if (lastSpec == null)
            {
                startIndex = lineAnalysis.MnemonicRange?.End.Character ?? lineAnalysis.EndCharacter;
            }
            else if (lastSpec.IsComplete)
            {
                startIndex = lastSpec.Range.End.Character;
            }
            else
            {
                startIndex = lastSpec.Range.Start.Character;
                currentSpecifierIndex--;
            }

            var instructionValidator = _instructionValidatorProvider.For(lineAnalysis.Mnemonic!);
            if (instructionValidator != null)
            {
                var allowedVectorDataTypes =
                    instructionValidator.GetPossibleVectorDataTypes(currentSpecifierIndex, lineAnalysis);
                var originalRangeForVectorDataType = source.GetOriginalRange(new Range(lineAnalysis.LineIndex,
                    startIndex,
                    lineAnalysis.LineIndex, prepPosition.Character));

                foreach (var allowedVectorDataType in allowedVectorDataTypes)
                {
                    var text = allowedVectorDataType.GetTextForm();

                    ret.Add(new CompletionItem()
                    {
                        Kind = CompletionItemKind.TypeParameter,
                        Label = _loc.EnumEntry(allowedVectorDataType, ILocalizationService.CompletionLabelTag),
                        Detail = _loc.EnumEntry(allowedVectorDataType, ILocalizationService.CompletionDescriptionTag),
                        Documentation = _symbolDoc.EnumEntry(allowedVectorDataType),
                        FilterText = $".{text}",
                        TextEdit = new TextEdit()
                        {
                            Range = originalRangeForVectorDataType,
                            NewText = $".{text}"
                        },
                        SortText = $"00{text}"
                    });
                }
            }
        }

        // Mnemonic completions
        if (lineAnalysis.PreFinishState == LineAnalysisState.HasMatches
            || (lineAnalysis.PreFinishState == LineAnalysisState.HasFullMatch &&
                lineAnalysis.MatchingMnemonics.Count > 1)
            || lineAnalysis.State == LineAnalysisState.Blank)
        {
            var target = (lineAnalysis.State == LineAnalysisState.Blank
                ? (await _instructionProvider.GetAllInstructions())
                : lineAnalysis.MatchingMnemonics).DistinctBy(m => m.Mnemonic);

            var originalRangeForMnemonic = source.GetOriginalRange(new Range(lineAnalysis.LineIndex,
                lineAnalysis.StartCharacter, lineAnalysis.LineIndex, prepPosition.Character));

            foreach (var match in target)
            {
                if (match.Mnemonic == lineAnalysis.Mnemonic?.Mnemonic)
                    continue;
                if ((match.VariantFlags & config.Flag) != 0)
                    continue;

                var ci = new CompletionItem()
                {
                    Kind = CompletionItemKind.Method,
                    Label = match.Mnemonic,
                    Detail = _instrDoc.InstructionDetail(match),
                    Documentation = _instrDoc.InstructionEntry(match),
                    TextEdit = new TextEdit()
                    {
                        Range = originalRangeForMnemonic,
                        NewText = match.Mnemonic
                    }
                };

                ret.Add(ci);
            }
        }

        // Operand completions
        if (lineAnalysis.PreFinishState == LineAnalysisState.MnemonicLoaded && lineAnalysis.Mnemonic!.HasOperands)
        {
            var token = this.DetermineTokenAtPosition(lineAnalysis, prepPosition);

            if (token.TokenDescriptor != null && token.TargetRange != null)
            {
                var originalRange = source.GetOriginalRange(token.TargetRange);

                if (token.TokenDescriptor.Type == OperandTokenType.Register)
                {
                    ret.AddRange(this.MakeCompletionItemsForRegister(originalRange,
                        token.TokenDescriptor.RegisterMask));
                }
                else if (token.TokenDescriptor.Type == OperandTokenType.ShiftType)
                {
                    ret.AddRange(this.MakeCompletionItemsForShiftType(originalRange,
                        token.TokenDescriptor.AllowedShiftTypes));
                }
                else if (token.TokenDescriptor.Type == OperandTokenType.Label)
                {
                    var text = source[token.TargetRange].Trim();
                    ret.AddRange(this.MakeCompletionItemsForLabel(originalRange, text, analyser));
                }
            }

            if (ret.Count == 0)
            {
                var existingChar = new Range(prepPosition.Line, prepPosition.Character - 1, prepPosition.Line,
                    prepPosition.Character);
                if (source[existingChar] == "R")
                {
                    ret.AddRange(this.MakeCompletionItemsForRegister(
                        source.GetOriginalRange(existingChar), RegisterExtensions.All));
                }
            }
        }

        return new CompletionList(ret, true);
    }

    private (OperandTokenDescriptor? TokenDescriptor, Range? TargetRange) DetermineTokenAtPosition(
        AnalysedLine lineAnalysis,
        Position position)
    {
        var mnemonic = lineAnalysis.Mnemonic;
        if (mnemonic == null)
            return (null, null);

        if (!mnemonic.HasOperands)
            return (null, null);

        if (position.Character < lineAnalysis.MnemonicRange?.End.Character)
            return (null, null);

        var analysedOperands = lineAnalysis.Operands;
        if (analysedOperands is null or { Count: 0 })
        {
            var firstOp = mnemonic.Operands[0];
            var firstDescriptor = firstOp.GetTokenDescriptors().FirstOrDefault();

            return (firstDescriptor, lineAnalysis.AnalysedRange.Trail(0));
        }

        AnalysedOperand? cursorIn = null;
        foreach (var analysedOperand in analysedOperands)
        {
            if (analysedOperand.Range.Contains(position) || (analysedOperand.ErrorRange?.Contains(position) ?? false))
            {
                cursorIn = analysedOperand;
                break;
            }
        }

        if (cursorIn != null)
        {
            if (cursorIn.Descriptor == null)
                return (null, null);
            if (cursorIn.Tokens == null && cursorIn.Descriptor.Type == OperandType.Shift)
                return (cursorIn.Descriptor.GetTokenDescriptors().FirstOrDefault(), cursorIn.ErrorRange);

            if (cursorIn.Tokens is null or { Count: 0 })
            {
                var firstDescriptor = cursorIn.Descriptor.GetTokenDescriptors().FirstOrDefault();

                return (firstDescriptor,
                    cursorIn.Descriptor.IsSingleToken
                        ? cursorIn.Range
                        : new Range(lineAnalysis.LineIndex, position.Character - 1, lineAnalysis.LineIndex,
                            position.Character));
            }

            if (cursorIn.Descriptor.Type is OperandType.RegisterOffset or OperandType.RegisterPreIndexed)
            {
                if (cursorIn.Tokens.Count == 2 && cursorIn.Tokens[1].Result == OperandTokenResult.Valid)
                {
                    if (position.Character > cursorIn.Tokens[1].Range.End.Character)
                    {
                        return ((cursorIn.Descriptor as BasicOperandDescriptor)!.MatchGroupsTokenMappings[3][1],
                            cursorIn.ErrorRange);
                    }
                }
            }

            foreach (var token in cursorIn.Tokens)
            {
                if (token.Range.Contains(position))
                {
                    if (cursorIn.Descriptor.IsSingleToken && cursorIn.ErrorRange != null)
                    {
                        return (token.TokenDescriptor, cursorIn.Range + cursorIn.ErrorRange);
                    }

                    return (token.TokenDescriptor,
                        new Range(token.Range.Start.Line, token.Range.Start.Character, token.Range.End.Line,
                            token.Range.End.Character));
                }
            }
        }

        return (null, null);
    }

    private IEnumerable<CompletionItem> MakeCompletionItemsForRegister(Range range, Register mask)
    {
        var values = Enum.GetValues<Register>().Where(r => mask.HasFlag(r));

        foreach (var register in values)
        {
            var text = register.GetIndex().ToString("00");

            var ci = new CompletionItem()
            {
                Kind = CompletionItemKind.Variable,
                Label = _loc.EnumEntry(register, ILocalizationService.CompletionLabelTag),
                Detail = _loc.EnumEntry(register, ILocalizationService.CompletionDescriptionTag),
                Documentation = _symbolDoc.EnumEntry(register),
                FilterText = register.ToString(),
                SortText = text,
                TextEdit = new TextEdit()
                {
                    Range = range,
                    NewText = register.ToString()
                }
            };

            yield return ci;
        }
    }

    private IEnumerable<CompletionItem> MakeCompletionItemsForShiftType(Range range, ShiftType[]? whitelist)
    {
        var values = whitelist ?? Enum.GetValues<ShiftType>();

        foreach (var shiftType in values)
        {
            var text = shiftType.ToString();

            var ci = new CompletionItem()
            {
                Kind = CompletionItemKind.Variable,
                Label = _loc.EnumEntry(shiftType, ILocalizationService.CompletionLabelTag),
                Detail = _loc.EnumEntry(shiftType, ILocalizationService.CompletionDescriptionTag),
                Documentation = _symbolDoc.EnumEntry(shiftType),
                FilterText = text,
                SortText = text,
                TextEdit = new TextEdit()
                {
                    Range = range,
                    NewText = text
                }
            };

            yield return ci;
        }
    }

    private IEnumerable<CompletionItem> MakeCompletionItemsForLabel(Range range, string data, ISourceAnalyser analyser)
    {
        var values = analyser.GetLabels()
            .Where(l => l.Label.StartsWith(data, StringComparison.InvariantCulture));

        foreach (var label in values)
        {
            var ci = new CompletionItem()
            {
                // TODO: add support for custom documentation
                Kind = label.TargetFunction == null ? CompletionItemKind.Field : CompletionItemKind.Method,
                Detail = label.TargetFunction == null
                    ? _loc["Label", ILocalizationService.CompletionDescriptionTag]
                    : _loc["FunctionSymbol", ILocalizationService.CompletionDescriptionTag],
                Label = label.Label,
                TextEdit = new TextEdit()
                {
                    Range = range,
                    NewText = label.Label
                }
            };

            yield return ci;
        }
    }

    private CompletionItem MakeCompletionItemForConditionCode(AnalysedLine lineAnalysis, ConditionCode ccValue,
        IPreprocessedSource source, Range? range = null)
    {
        var labelTag = lineAnalysis.Mnemonic!.IsVector
            ? ILocalizationService.CompletionLabelSimdTag
            : ILocalizationService.CompletionLabelTag;
        var detailTag = lineAnalysis.Mnemonic.IsVector
            ? ILocalizationService.CompletionDescriptionSimdTag
            : ILocalizationService.CompletionDescriptionTag;
        var docTag = lineAnalysis.Mnemonic.IsVector
            ? ILocalizationService.CompletionDocumentationSimdTag
            : ILocalizationService.CompletionDocumentationTag;

        var completionItem = new CompletionItem()
        {
            Kind = CompletionItemKind.Keyword,
            Label = _loc.EnumEntry(ccValue, labelTag),
            Detail = _loc.EnumEntry(ccValue, detailTag),
            Documentation = _symbolDoc.EnumEntry(ccValue, docTag),
            FilterText = ccValue.ToString(),
            TextEdit = new TextEdit()
            {
                Range = source.GetOriginalRange(range ?? lineAnalysis.ConditionCodeRange!),
                NewText = ccValue.ToString()
            },
            SortText = $"20{ccValue}"
        };

        return completionItem;
    }

    public override Task<CompletionItem> Handle(CompletionItem request, CancellationToken cancellationToken)
    {
        // This is used for Completion Resolve requests. We don't support that (yet?).
        return Task.FromResult(request);
    }

    protected override CompletionRegistrationOptions CreateRegistrationOptions(CompletionCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new CompletionRegistrationOptions()
        {
            DocumentSelector = Constants.ArmUalDocumentSelector,
            ResolveProvider = false, // we will see
            WorkDoneProgress = false,
            TriggerCharacters = new[] { " ", ",", ".", "[", "{", "-" }
        };
    }
}
