using Armfors.LanguageServer.Services;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Handlers;

public class DefinitionHandler : DefinitionHandlerBase
{
    private readonly DefinitionService _definitionService;

    public DefinitionHandler(DefinitionService definitionService)
    {
        _definitionService = definitionService;
    }

    public override async Task<LocationOrLocationLinks> Handle(DefinitionParams request,
        CancellationToken cancellationToken)
    {
        return await _definitionService.FindDefinition(request.TextDocument, request.Position);
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