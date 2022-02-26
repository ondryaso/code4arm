// CompletionHandler.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Handlers;

public class CompletionHandler : CompletionHandlerBase
{
    private readonly ISourceStore _sourceStore;

    public CompletionHandler(ISourceStore sourceStore)
    {
        _sourceStore = sourceStore;
    }

    public override async Task<CompletionList> Handle(CompletionParams request, CancellationToken cancellationToken)
    {
        var file = await _sourceStore.GetDocument(request.TextDocument.Uri);
        var line = await file.GetTextAsync(new Range(new Position(0, 0), request.Position));

        var compItems = new List<CompletionItem>();
        if (request.Position.Character < 4)
        {
            compItems.Add(new CompletionItem()
            {
                Kind = CompletionItemKind.Keyword,
                Label = "mov",
                Detail = "Moves shit",
                Documentation = new MarkupContent()
                {
                    Kind = MarkupKind.Markdown,
                    Value = "## MOV – Moves things.\nPls.\n\n[Arm® Documentation](https://google.com)"
                },
                TextEdit = new TextEdit()
                {
                    Range = new Range(request.Position, request.Position),
                    NewText = "mov"
                }
            });
        }
        else
        {
            for (var i = 0; i < 13; i++)
            {
                compItems.Add(new CompletionItem()
                {
                    Kind = CompletionItemKind.Variable,
                    Label = $"r{i}",
                    Detail = $"General-purpose register {i}",
                    SortText = $"{i:00}",
                    Documentation = null,
                    TextEdit = new TextEdit()
                    {
                        Range = new Range(request.Position, request.Position),
                        NewText = $"r{i}" + (request.Position.Character <= 6 ? ", " : "")
                    }
                });
            }
        }


        var list = new CompletionList(compItems);
        return list;
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
