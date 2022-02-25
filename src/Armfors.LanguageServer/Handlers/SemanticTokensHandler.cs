using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Handlers;

public class SemanticTokensHandler : SemanticTokensHandlerBase
{
    protected override SemanticTokensRegistrationOptions CreateRegistrationOptions(SemanticTokensCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new SemanticTokensRegistrationOptions()
        {
            Full = new SemanticTokensCapabilityRequestFull() {Delta = true},
            Range = true,
            DocumentSelector = Constants.ArmUalDocumentSelector,
            Legend = new SemanticTokensLegend()
            {
                TokenTypes = new Container<SemanticTokenType>(SemanticTokenType.Label, SemanticTokenType.Function),
                TokenModifiers = new Container<SemanticTokenModifier>()
            }
        };
    }

    protected override Task Tokenize(SemanticTokensBuilder builder, ITextDocumentIdentifierParams identifier,
        CancellationToken cancellationToken)
    {
        builder.Push(0, 0, 5, SemanticTokenType.Label, Enumerable.Empty<SemanticTokenModifier>());
        builder.Push(0, 7, 3, SemanticTokenType.Function, Enumerable.Empty<SemanticTokenModifier>());
        return Task.CompletedTask;
    }

    protected override Task<SemanticTokensDocument> GetSemanticTokensDocument(ITextDocumentIdentifierParams @params,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(new SemanticTokensDocument(RegistrationOptions.Legend));
    }
}