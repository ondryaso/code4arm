// CompletionHandler.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Extensions;
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

    public CompletionHandler(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore,
        IInstructionProvider instructionProvider, ILocalizationService localizationService)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
        _instructionProvider = instructionProvider;
        _loc = localizationService;
    }

    public override async Task<CompletionList> Handle(CompletionParams request, CancellationToken cancellationToken)
    {
        var source = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri);
        var analyser = _sourceAnalyserStore.GetAnalyser(source);
        await analyser.TriggerLineAnalysis(request.Position.Line, false);

        var lineAnalysis = analyser.GetLineAnalysis(request.Position.Line);
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

        if (lineAnalysis.PreFinishState == LineAnalysisState.HasFullMatch)
        {
            if (!lineAnalysis.SetsFlags && lineAnalysis.Mnemonic!.HasSetFlagsVariant &&
                lineAnalysis.ConditionCodeRange == null)
            {
                ret.Add(new CompletionItem()
                {
                    Kind = CompletionItemKind.Event,
                    Label = _loc["Set flags", ILocalizationService.CompletionLabelTag],
                    Detail = _loc["Set flags", ILocalizationService.CompletionDescriptionTag],
                    Documentation = _loc.HasValue("Set flags", ILocalizationService.CompletionDocumentationTag)
                        ? new MarkupContent { Kind = MarkupKind.Markdown, Value = _loc["Set flags", ILocalizationService.CompletionDocumentationTag] }
                        : null,
                    FilterText = "S",
                    TextEdit = new TextEdit()
                    {
                        Range = new Range(lineAnalysis.LineIndex, request.Position.Character, lineAnalysis.LineIndex,
                            request.Position.Character),
                        NewText = "S"
                    },
                    SortText = "00S"
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
                    var completionItem = this.MakeCompletionItemForConditionCode(lineAnalysis, ccValue);
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

                    var completionItem = this.MakeCompletionItemForConditionCode(lineAnalysis, ccValue, range);
                    ret.Add(completionItem);
                }
            }
        }

        if (lineAnalysis.PreFinishState == LineAnalysisState.HasMatches
            || (lineAnalysis.PreFinishState == LineAnalysisState.HasFullMatch && lineAnalysis.MatchingMnemonics.Count > 1)
            || lineAnalysis.State == LineAnalysisState.Blank)
        {
            var target = (lineAnalysis.State == LineAnalysisState.Blank
                ? (await _instructionProvider.GetAllInstructions())
                : lineAnalysis.MatchingMnemonics).Select(m => m.Mnemonic).Distinct();
            
            foreach (var match in target)
            {
                if (match == lineAnalysis.Mnemonic?.Mnemonic)
                    continue;

                var ci = new CompletionItem()
                {
                    Kind = CompletionItemKind.Method,
                    Label = match,
                    TextEdit = new TextEdit()
                    {
                        Range = new Range(lineAnalysis.LineIndex, lineAnalysis.StartCharacter, lineAnalysis.LineIndex,
                            request.Position.Character),
                        NewText = match
                    }
                };

                ret.Add(ci);
            }
        }

        return new CompletionList(ret, true);
    }

    private CompletionItem MakeCompletionItemForConditionCode(AnalysedLine lineAnalysis, ConditionCode ccValue,
        Range? range = null)
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
            Documentation = _loc.HasValue(ccValue, docTag)
                ? new MarkupContent { Kind = MarkupKind.Markdown, Value = _loc.EnumEntry(ccValue, docTag) }
                : null,
            FilterText = ccValue.ToString(),
            TextEdit = new TextEdit()
            {
                Range = range ?? lineAnalysis.ConditionCodeRange!,
                NewText = ccValue.ToString()
            },
            SortText = $"10{ccValue}"
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
