using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Handlers;

public class DefinitionHandler : DefinitionHandlerBase
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;

    public DefinitionHandler(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
    }

    public override async Task<LocationOrLocationLinks> Handle(DefinitionParams request,
        CancellationToken cancellationToken)
    {
        var source = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri);
        var analyser = _sourceAnalyserStore.GetAnalyser(source);

        await analyser.TriggerFullAnalysis();

        var prepPosition = source.GetPreprocessedPosition(request.Position);
        var token = analyser.FindTokenAtPosition(prepPosition);
        if (token == null)
            return new LocationOrLocationLinks();

        string? label = null;

        if (token.Type == AnalysedTokenType.OperandToken)
        {
            var operandToken = token.OperandToken!;
            if (operandToken.Type == OperandTokenType.Label && operandToken.Data.TargetLabel != null)
            {
                label = operandToken.Data.TargetLabel.Label;
            }
        }

        if (token.Type == AnalysedTokenType.Label)
        {
            label = token.Label!.Label;
        }

        if (label != null)
        {
            var sourceLabel = analyser.GetLabel(label);
            if (sourceLabel == null)
                return new LocationOrLocationLinks(); // TODO: log

            return new LocationOrLocationLinks(new Location()
            {
                Range = source.GetOriginalRange(sourceLabel.Range),
                Uri = request.TextDocument.Uri
            });
        }

        return new LocationOrLocationLinks();
    }

    protected override DefinitionRegistrationOptions CreateRegistrationOptions(DefinitionCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new DefinitionRegistrationOptions()
        {
            DocumentSelector = Constants.ArmUalDocumentSelector
        };
    }
}
