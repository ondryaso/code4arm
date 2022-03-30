using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Services;

public class DefinitionService
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;

    public DefinitionService(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
    }

    public async Task<LocationOrLocationLinks> FindDefinition(TextDocumentIdentifier document, Position position)
    {
        var source = await _sourceStore.GetPreprocessedDocument(document.Uri);
        var analyser = _sourceAnalyserStore.GetAnalyser(source);

        await analyser.TriggerFullAnalysis();

        var token = analyser.FindTokenAtPosition(position);
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
                Uri = document.Uri
            });
        }

        return new LocationOrLocationLinks();
    }
}