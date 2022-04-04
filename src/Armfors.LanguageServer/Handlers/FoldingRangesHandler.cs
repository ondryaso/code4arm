using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Handlers;

public class FoldingRangesHandler : FoldingRangeHandlerBase
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;

    public FoldingRangesHandler(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
    }

    public override async Task<Container<FoldingRange>?> Handle(FoldingRangeRequestParam request,
        CancellationToken cancellationToken)
    {
        var originalSource = await _sourceStore.GetDocument(request.TextDocument.Uri);
        var source = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri);
        var analyser = _sourceAnalyserStore.GetAnalyser(source);

        await analyser.TriggerFullAnalysis();
        var originalLines = -1;

        return new Container<FoldingRange>(analyser.GetFunctions().Select(f => new FoldingRange()
        {
            Kind = FoldingRangeKind.Region,
            StartLine = source.GetOriginalLine(f.StartLine),
            EndLine = f.EndLine == -1
                ? (originalLines == -1
                    ? (originalLines = originalSource.Lines - 1)
                    : originalLines) // Lazy loading of the Lines property
                : source.GetOriginalLine(f.EndLine)
        }));
    }

    protected override FoldingRangeRegistrationOptions CreateRegistrationOptions(FoldingRangeCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new FoldingRangeRegistrationOptions()
        {
            DocumentSelector = Constants.ArmUalDocumentSelector
        };
    }
}