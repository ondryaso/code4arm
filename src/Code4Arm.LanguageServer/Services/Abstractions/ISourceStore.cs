// ISourceStore.cs
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

using Code4Arm.LanguageServer.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.Services.Abstractions;

/// <summary>
/// Manages source files.
/// </summary>
public interface ISourceStore
{
    /// <summary>
    /// Signalises that a document's content is now managed by the client which notifies the service of changes
    /// using <see cref="ApplyFullChange"/> or <see cref="ApplyIncrementalChange"/>.
    /// </summary>
    /// <param name="document">The document model including its URI and text.</param>
    /// <exception cref="InvalidOperationException">When the document is already open (managed).</exception>
    Task LoadDocument(TextDocumentItem document);

    /// <summary>
    /// Returns the currently valid representation of a document, managed or unmanaged.
    /// </summary>
    /// <param name="uri">URI of the document.</param>
    Task<ISource> GetDocument(DocumentUri uri);

    /// <summary>
    /// Returns the preprocessed version of the currently valid representation of a managed document.
    /// </summary>
    /// <param name="uri">URI of the document.</param>
    Task<IPreprocessedSource> GetPreprocessedDocument(DocumentUri uri);

    /// <summary>
    /// Signalises that a document's content is not managed by the client anymore and its underlying representation
    /// (e.g. contents saved in the filesystem), which is the one <paramref name="uri"/> points to, represents the
    /// document's actual state now.
    /// </summary>
    /// <param name="uri">URI of the document.</param>
    /// <exception cref="InvalidOperationException">When the document is not open (unmanaged).</exception>
    Task CloseDocument(DocumentUri uri);

    /// <summary>
    /// Returns true if a document is managed by the client.
    /// </summary>
    /// <param name="uri">URI of the document.</param>
    Task<bool> IsOpen(DocumentUri uri);

    /// <summary>
    /// Sets the in-memory contents of a managed document to <paramref name="text"/>.
    /// </summary>
    /// <param name="uri">URI of the document.</param>
    /// <param name="text">New full contents of the document.</param>
    /// <param name="version"></param>
    /// <exception cref="InvalidOperationException">When used on an unmanaged document – one that hasn't been loaded
    /// using <see cref="LoadDocument"/> before.</exception>
    Task ApplyFullChange(DocumentUri uri, string text, int? version);

    /// <summary>
    /// Updates a range in a managed document to <paramref name="text"/>.
    /// </summary>
    /// <param name="uri">URI of the document.</param>
    /// <param name="range">The range in the document to update.</param>
    /// <param name="text">The text to place in the specified range.</param>
    /// <param name="version"></param>
    /// <exception cref="InvalidOperationException">When used on an unmanaged document – one that hasn't been loaded
    /// using <see cref="LoadDocument"/> before.</exception>
    Task ApplyIncrementalChange(DocumentUri uri, Range range, string text, int? version);
}
