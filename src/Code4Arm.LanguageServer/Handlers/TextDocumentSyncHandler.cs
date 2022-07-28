// TextDocumentSyncHandler.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using Code4Arm.LanguageServer.Services.Abstractions;
using MediatR;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Server.Capabilities;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.Handlers;

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
    private readonly ISourceAnalyserStore _analyserStore;
    private readonly IDiagnosticsPublisher _diagnosticsPublisher;

    public TextDocumentSyncHandler(ISourceStore sourceStore, ISourceAnalyserStore analyserStore,
        IDiagnosticsPublisher diagnosticsPublisher)
    {
        _sourceStore = sourceStore;
        _analyserStore = analyserStore;
        _diagnosticsPublisher = diagnosticsPublisher;
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
    public override async Task<Unit> Handle(DidOpenTextDocumentParams request, CancellationToken cancellationToken)
    {
        await _sourceStore.LoadDocument(request.TextDocument).ConfigureAwait(false);
        await _diagnosticsPublisher.ClearDiagnostics(request.TextDocument.Uri, request.TextDocument.Version)
            .ConfigureAwait(false);

        var source = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri).ConfigureAwait(false);
        var analyser = _analyserStore.GetAnalyser(source);
        await analyser.TriggerFullAnalysis();

        return Unit.Value;
    }

    /// <summary>
    /// Called when an open document is changed.
    /// </summary>
    /// <remarks>
    /// <a href="https://microsoft.github.io/language-server-protocol/specifications/specification-current/#textDocument_didChange">LSP docs</a>
    /// </remarks>
    /// <returns>Nothing (a <see cref="Unit"/>).</returns>
    public override async Task<Unit> Handle(DidChangeTextDocumentParams request, CancellationToken cancellationToken)
    {
        var source = await _sourceStore.GetDocument(request.TextDocument.Uri);
        var preprocessedSource = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri);
        
        var analyser = _analyserStore.GetAnalyser(preprocessedSource);

        foreach (var change in request.ContentChanges)
        {
            if (change.Range is null)
            {
                await _sourceStore.ApplyFullChange(request.TextDocument.Uri, change.Text, request.TextDocument.Version)
                    .ConfigureAwait(false);
                await analyser.TriggerFullAnalysis();
            }
            else
            {
                /*
                var start = change.Range.Start;
                var end = change.Range.End;
                
                var isSingleLine = start.Line == end.Line || (end.Character == 0 && end.Line == start.Line + 1);
                var originalLine = source[new Range(start.Line, 0, start.Line + 1, 0)].Trim();
                var appendedToEnd = start.Character == originalLine.Length;*/

                await _sourceStore.ApplyIncrementalChange(request.TextDocument.Uri, change.Range, change.Text,
                    request.TextDocument.Version).ConfigureAwait(false);

                /*if (isSingleLine)
                {
                    await analyser.TriggerLineAnalysis(start.Line, appendedToEnd);
                }
                else
                {
                    for (var line = start.Line; line <= end.Line; line++)
                    {
                        await analyser.TriggerLineAnalysis(line, false);
                    }
                }*/
                
                await analyser.TriggerFullAnalysis();
            }
        }

        return Unit.Value;
    }

    /// <summary>
    /// Called when an open document is closed.
    /// </summary>
    /// <remarks>
    /// The document's master now exists where the document's Uri points to (e.g. on disk).
    /// <a href="https://microsoft.github.io/language-server-protocol/specifications/specification-current/#textDocument_didClose">LSP docs</a>
    /// </remarks>
    /// <returns>Nothing (a <see cref="Unit"/>).</returns>
    public override async Task<Unit> Handle(DidCloseTextDocumentParams request, CancellationToken cancellationToken)
    {
        await _sourceStore.CloseDocument(request.TextDocument.Uri).ConfigureAwait(false);
        await _diagnosticsPublisher.ClearDiagnostics(request.TextDocument.Uri, null).ConfigureAwait(false);

        return Unit.Value;
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
