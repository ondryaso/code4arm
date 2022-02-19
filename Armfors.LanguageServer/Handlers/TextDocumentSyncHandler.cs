// TextDocumentSyncHandler.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.Models.Abstractions;
using Armfors.LanguageServer.Services.Abstractions;
using MediatR;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Server.Capabilities;

namespace Armfors.LanguageServer.Handlers;

/// <summary>
/// A text document synchronization handler provides an interface between the server and a client
/// for exchanging information about the contents of text files opened and managed by the client.
/// </summary>
/// <remarks>
/// This handler covers <a href="https://microsoft.github.io/language-server-protocol/specifications/specification-3-16/#textDocument_synchronization">this section</a>
/// of the LSP specification.
/// </remarks>
public class TextDocumentSyncHandler : TextDocumentSyncHandlerBase
{
    private readonly ISourceStore _sourceStore;

    public TextDocumentSyncHandler(ISourceStore sourceStore)
    {
        _sourceStore = sourceStore;
    }
    
    /// <summary>
    /// Called when the client opens a text document.
    /// </summary>
    /// <remarks>
    /// The document's content is now managed by the client and the server must not try to read the document's content
    /// using the document's Uri – instead, it has to keep it in sync using DidChangeTextDocument notifications.
    /// <a href="https://microsoft.github.io/language-server-protocol/specifications/specification-current/#textDocument_didOpen">LSP docs</a>.
    /// </remarks>
    /// <returns>Nothing (a <see cref="Unit"/>).</returns>
    public override Task<Unit> Handle(DidOpenTextDocumentParams request, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Called when an open document is changed.
    /// </summary>
    /// <remarks>
    /// <a href="https://microsoft.github.io/language-server-protocol/specifications/specification-current/#textDocument_didChange">LSP docs</a>
    /// </remarks>
    /// <returns>Nothing (a <see cref="Unit"/>).</returns>
    public override Task<Unit> Handle(DidChangeTextDocumentParams request, CancellationToken cancellationToken)
    {
        
        throw new NotImplementedException();
    }

    /// <summary>
    /// Called when an open document is closed.
    /// </summary>
    /// <remarks>
    /// The document's master now exists where the document's Uri points to (e.g. on disk).
    /// <a href="https://microsoft.github.io/language-server-protocol/specifications/specification-current/#textDocument_didClose">LSP docs</a>
    /// </remarks>
    /// <returns>Nothing (a <see cref="Unit"/>).</returns>
    public override Task<Unit> Handle(DidCloseTextDocumentParams request, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// Used by the LSP server library to route requests for files.
    /// </summary>
    public override TextDocumentAttributes GetTextDocumentAttributes(DocumentUri uri)
    {
        return new TextDocumentAttributes(uri, "file", Constants.ArmUalLanguageId);
    }

    /// <summary>
    /// Called when an open document is saved.
    /// </summary>
    /// <remarks>
    /// <a href="https://microsoft.github.io/language-server-protocol/specifications/specification-current/#textDocument_didSave">LSP docs</a>
    /// </remarks>
    /// <returns>Nothing (a <see cref="Unit"/>).</returns>
    public override Task<Unit> Handle(DidSaveTextDocumentParams request, CancellationToken cancellationToken)
    {
        // We don't need to handle save events in any particular way.
        // (Because of the registration options, we shouldn't even get them anyway.)
        return Unit.Task;
    }

    /// <summary>
    /// Creates a registration options object describing the operation of this document sync handler.
    /// </summary>
    protected override TextDocumentSyncRegistrationOptions CreateRegistrationOptions(
        SynchronizationCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new TextDocumentSyncRegistrationOptions
        {
            DocumentSelector = Constants.ArmUalDocumentSelector,
            // Documents are synced by sending the full content on open.
            // After that, only incremental updates to the document are sent.
            Change = TextDocumentSyncKind.Incremental,
            // Save notifications should not be sent
            Save = null
        };
    }
}
