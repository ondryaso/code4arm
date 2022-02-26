// SignatureHelpHandler.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Handlers;

public class SignatureHelpHandler : SignatureHelpHandlerBase
{
    public override Task<SignatureHelp?> Handle(SignatureHelpParams request, CancellationToken cancellationToken)
    {
        if (request.Position.Character >= 10)
        {
            return Task.FromResult<SignatureHelp?>(null);
        }

        var sh = new SignatureHelp()
        {
            Signatures = new Container<SignatureInformation>(new SignatureInformation()
            {
                Label = "MOV <Rd>, <Rn>",
                ActiveParameter = request.Position.Character switch
                {
                    < 4 => null,
                    < 7 => 0,
                    < 10 => 1,
                    _ => null
                },
                Documentation = new MarkupContent()
                {
                    Value = ""
                },
                Parameters = new Container<ParameterInformation>(new ParameterInformation()
                    {
                        Label = new ParameterInformationLabel((4, 8)),
                        Documentation = new MarkupContent()
                        {
                            Kind = MarkupKind.Markdown,
                            Value =
                                "## MOV – Moves things.\nPls.\n\n[Arm® Documentation](command:workbench.action.findInFiles)"
                        }
                    },
                    new ParameterInformation()
                    {
                        Label = new ParameterInformationLabel((10, 14)),
                        Documentation = "Source"
                    })
            }, new SignatureInformation()
            {
                Label = "MOV <Rd>, #const",
                ActiveParameter = request.Position.Character switch
                {
                    < 4 => null,
                    < 7 => 0,
                    < 10 => 1,
                    _ => null
                },
                Documentation = new MarkupContent()
                {
                    Kind = MarkupKind.Markdown,
                    Value = "pls **const**"
                },
                Parameters = new Container<ParameterInformation>(new ParameterInformation()
                    {
                        Label = new ParameterInformationLabel((4, 8)),
                        Documentation = new MarkupContent()
                        {
                            Kind = MarkupKind.Markdown,
                            Value =
                                "**MOV – Moves const things.**\n\nPls.\n\n[Arm® Documentation](command:workbench.action.findInFiles)"
                        }
                    },
                    new ParameterInformation()
                    {
                        Label = new ParameterInformationLabel((10, 14)),
                        Documentation = "Source"
                    })
            }),
            ActiveSignature = 1,
            ActiveParameter = null
        };

        return Task.FromResult(sh);
    }

    protected override SignatureHelpRegistrationOptions CreateRegistrationOptions(SignatureHelpCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new SignatureHelpRegistrationOptions()
        {
            DocumentSelector = Constants.ArmUalDocumentSelector
        };
    }
}
