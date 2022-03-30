using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Handlers;

public class DocumentSymbolsHandler : DocumentSymbolHandlerBase
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;

    public DocumentSymbolsHandler(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
    }

    public override async Task<SymbolInformationOrDocumentSymbolContainer> Handle(DocumentSymbolParams request,
        CancellationToken cancellationToken)
    {
        var source = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri);
        var analyser = _sourceAnalyserStore.GetAnalyser(source);

        await analyser.TriggerFullAnalysis();

        return SymbolInformationOrDocumentSymbolContainer.From(analyser.GetLabels().Select(l =>
            new SymbolInformationOrDocumentSymbol(new SymbolInformation()
            {
                Kind = l.IsCodeLabel ? SymbolKind.Function : SymbolKind.Constant, // TODO: decide based on whether the symbol represents a function label
                Name = l.Label,
                Location = new Location {Uri = request.TextDocument.Uri, Range = source.GetOriginalRange(l.Range)}
            })));
    }

    protected override DocumentSymbolRegistrationOptions CreateRegistrationOptions(DocumentSymbolCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new DocumentSymbolRegistrationOptions()
        {
            Label = Constants.ArmUalLanguageName,
            DocumentSelector = Constants.ArmUalDocumentSelector
        };
    }
}