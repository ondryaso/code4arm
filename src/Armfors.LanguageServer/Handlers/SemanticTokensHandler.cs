using System.Collections.Concurrent;
using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Handlers;

public class SemanticTokensHandler : SemanticTokensHandlerBase
{
    private readonly ITokenizer _tokenizer;

    private static readonly SemanticTokenType[] UsedTokenTypes = new[]
    {
        ArmSemanticTokenType.Instruction, ArmSemanticTokenType.Directive, ArmSemanticTokenType.Register,
        ArmSemanticTokenType.ConditionCode, ArmSemanticTokenType.SetsFlagsFlag, ArmSemanticTokenType.VectorDataType,
        ArmSemanticTokenType.InstructionSizeQualifier, SemanticTokenType.Label, SemanticTokenType.Method
    };

    private static readonly SemanticTokenModifier[] UsedTokenModifiers = new[]
    {
        ArmSemanticTokenModifier.Conditional, ArmSemanticTokenModifier.SetsFlags,
        ArmSemanticTokenModifier.VectorInstruction
    };

    private readonly ConcurrentDictionary<DocumentUri, SemanticTokensDocument> _semanticTokensDocuments = new();

    public SemanticTokensHandler(ITokenizer tokenizer)
    {
        _tokenizer = tokenizer;
    }

    protected override async Task Tokenize(SemanticTokensBuilder builder, ITextDocumentIdentifierParams identifier,
        CancellationToken cancellationToken)
    {
        await _tokenizer.Tokenize(identifier.TextDocument.Uri, builder);
    }

    protected override Task<SemanticTokensDocument> GetSemanticTokensDocument(ITextDocumentIdentifierParams @params,
        CancellationToken cancellationToken)
    {
        var document = _semanticTokensDocuments.GetOrAdd(@params.TextDocument.Uri,
            _ => new SemanticTokensDocument(this.RegistrationOptions));

        return Task.FromResult(document);
    }

    protected override SemanticTokensRegistrationOptions CreateRegistrationOptions(SemanticTokensCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new SemanticTokensRegistrationOptions()
        {
            Full = new SemanticTokensCapabilityRequestFull() { Delta = true },
            Range = true,
            DocumentSelector = Constants.ArmUalDocumentSelector,
            Legend = new SemanticTokensLegend()
            {
                TokenTypes = new Container<SemanticTokenType>(UsedTokenTypes),
                TokenModifiers = new Container<SemanticTokenModifier>(UsedTokenModifiers)
            }
        };
    }
}
