// CompletionHandler.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Extensions;
using Armfors.LanguageServer.Models.Abstractions;
using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Handlers;

public class CompletionHandler : CompletionHandlerBase
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;
    private readonly IInstructionProvider _instructionProvider;
    private readonly ILocalizationService _loc;
    private readonly IDocumentationProvider _doc;

    public CompletionHandler(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore,
        IInstructionProvider instructionProvider, ILocalizationService localizationService,
        IDocumentationProvider documentationProvider)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
        _instructionProvider = instructionProvider;
        _loc = localizationService;
        _doc = documentationProvider;
    }

    public override async Task<CompletionList> Handle(CompletionParams request, CancellationToken cancellationToken)
    {
        var source = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri);
        var analyser = _sourceAnalyserStore.GetAnalyser(source);
        var prepPosition = source.GetPreprocessedPosition(request.Position);

        await analyser.TriggerLineAnalysis(source.GetPreprocessedLine(prepPosition.Line), false);

        var lineAnalysis = analyser.GetLineAnalysis(source.GetPreprocessedLine(prepPosition.Line));
        if (lineAnalysis == null)
        {
            return new CompletionList(false);
        }

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
                    Documentation = _doc["Set flags"],
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

            var allowedVectorDataTypes = lineAnalysis.Mnemonic.GetPossibleVectorDataTypes(currentSpecifierIndex);
            var originalRangeForVectorDataType = source.GetOriginalRange(new Range(lineAnalysis.LineIndex, startIndex,
                lineAnalysis.LineIndex, prepPosition.Character));

            foreach (var allowedVectorDataType in allowedVectorDataTypes)
            {
                var text = allowedVectorDataType.GetTextForm();

                ret.Add(new CompletionItem()
                {
                    Kind = CompletionItemKind.TypeParameter,
                    Label = _loc.EnumEntry(allowedVectorDataType, ILocalizationService.CompletionLabelTag),
                    Detail = _loc.EnumEntry(allowedVectorDataType, ILocalizationService.CompletionDescriptionTag),
                    Documentation = _doc.EnumEntry(allowedVectorDataType),
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

                var ci = new CompletionItem()
                {
                    Kind = CompletionItemKind.Method,
                    Label = match.Mnemonic,
                    Detail = _doc.InstructionDetail(match),
                    Documentation = _doc.InstructionEntry(match),
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
            }
        }

        return new CompletionList(ret, true);
    }

    private (OperandToken? TokenDescriptor, Range? TargetRange) DetermineTokenAtPosition(AnalysedLine lineAnalysis,
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
            return (SingleOrFirstTokenDescriptor(firstOp), lineAnalysis.AnalysedRange.Trail(0));
        }

        AnalysedOperand? cursorIn = null;
        foreach (var analysedOperand in analysedOperands)
        {
            if (analysedOperand.Range.Contains(position))
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
                return (cursorIn.Descriptor.MatchGroupsTokenMappings[0].First().Value, cursorIn.ErrorRange);
            if (cursorIn.Tokens is null or { Count: 0 })
                return (SingleOrFirstTokenDescriptor(cursorIn.Descriptor),
                    cursorIn.Descriptor.IsSingleToken
                        ? cursorIn.Range
                        : new Range(lineAnalysis.LineIndex, position.Character - 1, lineAnalysis.LineIndex,
                            position.Character));

            foreach (var token in cursorIn.Tokens)
            {
                if (token.Range.Contains(position))
                {
                    if (cursorIn.Descriptor.IsSingleToken && cursorIn.ErrorRange != null)
                    {
                        return (token.Token, cursorIn.Range + cursorIn.ErrorRange);
                    }

                    return (token.Token,
                        new Range(token.Range.Start.Line, token.Range.Start.Character, token.Range.End.Line,
                            token.Range.End.Character));
                }
            }
        }

        return (null, null);
    }

    private static OperandToken? SingleOrFirstTokenDescriptor(OperandDescriptor descriptor) =>
        descriptor.IsSingleToken
            ? descriptor.SingleToken
            : descriptor.MatchGroupsTokenMappings?.FirstOrDefault().Value.FirstOrDefault().Value;

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
                Documentation = _doc.EnumEntry(register),
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
                Documentation = _doc.EnumEntry(shiftType),
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
            Documentation = _doc.EnumEntry(ccValue, docTag),
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
