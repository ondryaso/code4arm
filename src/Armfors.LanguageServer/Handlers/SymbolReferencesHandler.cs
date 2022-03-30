using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Handlers;

public class SymbolReferencesHandler : ReferencesHandlerBase
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;

    public SymbolReferencesHandler(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
    }

    public override async Task<LocationContainer> Handle(ReferenceParams request, CancellationToken cancellationToken)
    {
        var source = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri);
        var analyser = _sourceAnalyserStore.GetAnalyser(source);

        await analyser.TriggerFullAnalysis();

        var token = analyser.FindTokenAtPosition(request.Position);
        if (token == null)
            return new LocationContainer();

        // Labels & registers
        if (token.Type == AnalysedTokenType.OperandToken)
        {
            var operandToken = token.OperandToken!;
            if (operandToken.Type == OperandTokenType.Label)
            {
                var targetLabel = operandToken.Data.TargetLabel;
                if (targetLabel == null)
                    return new LocationContainer();

                return MakeLocationsForLabel(request, analyser, targetLabel);
            }
            
            if (operandToken.Type == OperandTokenType.Register)
            {
                var targetRegister = operandToken.Data.Register;
                return MakeLocationsForRegister(request, analyser, targetRegister);
            }
        }
        else if (token.Type == AnalysedTokenType.Label)
        {
            return MakeLocationsForLabel(request, analyser, token.Label!);
        }

        return new LocationContainer();
    }

    private static LocationContainer MakeLocationsForLabel(ReferenceParams request, ISourceAnalyser analyser,
        AnalysedLabel targetLabel)
    {
        var usages = analyser.FindLabelOccurrences(targetLabel.Label, request.Context.IncludeDeclaration);
        return new LocationContainer(usages.Select(u => new Location()
        {
            Range = u.TokenRange,
            Uri = request.TextDocument.Uri
        }));
    }

    private static LocationContainer MakeLocationsForRegister(ReferenceParams request, ISourceAnalyser analyser,
        Register targetRegister)
    {
        var usages = analyser.FindRegisterOccurrences(targetRegister);
        return new LocationContainer(usages.Select(u => new Location()
        {
            Range = u.TokenRange,
            Uri = request.TextDocument.Uri
        }));
    }

    protected override ReferenceRegistrationOptions CreateRegistrationOptions(ReferenceCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new ReferenceRegistrationOptions()
        {
            DocumentSelector = Constants.ArmUalDocumentSelector
        };
    }
}