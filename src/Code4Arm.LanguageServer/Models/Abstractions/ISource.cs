// ISource.cs
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

using System.Collections.Generic;
using Code4Arm.LanguageServer.Extensions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.Models.Abstractions;

/// <summary>
/// Represents a textual source document.
/// </summary>
public interface ISource
{
    /// <summary>
    /// If true, this objects is the currently valid representation of the document identified
    /// by <see cref="Uri"/>. 
    /// </summary>
    /// <remarks>
    /// This property changes e.g. when a document is 'opened' or 'closed' by the client – on instances
    /// of <see cref="ISource"/> that have been created before this event and kept in memory.
    /// </remarks>
    bool IsValidRepresentation { get; }

    /// <summary>
    /// URI of the document.
    /// </summary>
    DocumentUri Uri { get; }

    /// <summary>
    /// The last version number of the document
    /// </summary>
    /// <remarks>
    /// The version number of a document will increase after each change, including undo/redo.
    /// The number doesn't need to be consecutive.
    /// <a href="https://microsoft.github.io/language-server-protocol/specifications/specification-3-16/#versionedTextDocumentIdentifier">LSP docs</a>.
    /// </remarks>
    int? Version { get; }

    /// <summary>
    /// The total number of lines.
    /// </summary>
    int Lines
    {
        get
        {
            var text = this.Text;
            return text.GetPositionForIndex(text.Length - 1).Line + 1;
        }
    }

    /// <summary>
    /// The current contents of the document.
    /// </summary>
    string Text { get; }

    /// <summary>
    /// Returns a substring of the document's text on the position given by a provided range.
    /// </summary>
    /// <param name="range">The range to get text in.</param>
    string this[Range range] { get; }

    /// <summary>
    /// Returns a substring of the document's text on the position given by a line index.
    /// </summary>
    /// <param name="line">The line index to get text on.</param>
    string this[int line] { get; }

    /// <summary>
    /// Iterates through lines in the document's text.
    /// Lines include newline characters converted to \n.
    /// </summary>
    /// <returns>An <see cref="IEnumerable{T}"/> of lines.</returns>
    IEnumerable<string> GetLines();

    /// <summary>
    /// Asynchronously determines and returns the current contents of the document.
    /// </summary>
    Task<string> GetTextAsync();

    /// <summary>
    /// Asynchronously determines and returns a substring of the document's text on the position given by
    /// a provided range.
    /// </summary>
    /// <param name="range">The range to get text in.</param>
    Task<string> GetTextAsync(Range range);

    /// <summary>
    /// Asynchronously determines and returns a substring of the document's text on the position given by a line index.
    /// </summary>
    /// <param name="line">The line index to get text on.</param>
    Task<string> GetTextAsync(int line);

    /// <summary>
    /// Asynchronously iterates through lines in the document's text.
    /// Lines include newline characters converted to \n.
    /// </summary>
    /// <returns>An <see cref="IAsyncEnumerable{T}"/> of lines.</returns>
    IAsyncEnumerable<string> GetLinesAsyncEnumerable();

    bool SupportsSyncOperations { get; }
    bool SupportsAsyncOperations { get; }
    bool SupportsSyncLineIterator { get; }
    bool SupportsAsyncLineIterator { get; }
}