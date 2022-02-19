// FileSourceStore.cs
// Author: Ondřej Ondryáš

using System.Collections.Concurrent;
using System.IO.Abstractions;
using Armfors.LanguageServer.Models;
using Armfors.LanguageServer.Models.Abstractions;
using Armfors.LanguageServer.Services.Abstractions;
using Microsoft.Extensions.Logging;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Services;

public class FileSourceStore : ISourceStore
{
    private readonly ILogger<FileSourceStore> _logger;
    private readonly IFileSystem _fileSystem;

    private readonly ConcurrentDictionary<DocumentUri, BufferedSource> _managedDocs = new();
    private readonly ConcurrentDictionary<DocumentUri, FileSource> _unmanagedDocs = new();

    public FileSourceStore(ILogger<FileSourceStore> logger, IFileSystem fileSystem)
    {
        _logger = logger;
        _fileSystem = fileSystem;
    }

    public Task LoadDocument(TextDocumentItem document)
    {
        // First check for existence so that we don't construct a BufferedSource pointlessly
        if (_managedDocs.ContainsKey(document.Uri))
        {
            throw new InvalidOperationException("The file has already been opened.");
        }

        var source = new BufferedSource(document.Uri, document.Text, document.Version);

        // This does a second existence check 
        if (!_managedDocs.TryAdd(document.Uri, source))
        {
            throw new InvalidOperationException("The file has already been opened.");
        }

        // If we also have a FileSource representing the filesystem version of the document,
        // mark it as invalid
        if (_unmanagedDocs.TryGetValue(document.Uri, out var unmanagedSource))
        {
            unmanagedSource.IsValidRepresentation = false;
        }

        return Task.CompletedTask;
    }

    public Task<ISource> GetDocument(DocumentUri uri)
    {
        if (_managedDocs.TryGetValue(uri, out var source))
        {
            return Task.FromResult(source as ISource);
        }
        else
        {
            return Task.FromResult(this.GetOrCreateFileSource(uri) as ISource);
        }
    }

    public Task CloseDocument(DocumentUri uri)
    {
        if (!_managedDocs.TryRemove(uri, out var source))
        {
            throw new InvalidOperationException("The file is not opened.");
        }

        source.IsValidRepresentation = false;

        // If we also have a FileSource representing the filesystem version of the document,
        // mark it as valid
        if (_unmanagedDocs.TryGetValue(uri, out var unmanagedSource))
        {
            unmanagedSource.IsValidRepresentation = true;
        }

        return Task.CompletedTask;
    }

    public Task<bool> IsOpen(DocumentUri uri)
    {
        return Task.FromResult(_managedDocs.ContainsKey(uri));
    }

    public Task ApplyFullChange(DocumentUri uri, string text, int? version)
    {
        var source = this.GetSourceOrThrow(uri);

        _logger.LogDebug("Applying a full change to document {Uri} (from {CurrentVersion} to {GotVersion}).",
            uri.ToString(), source.Version, version);

        if (source.Version > version)
        {
            _logger.LogError(
                "Got a full change for document {Uri} with version {GotVersion} lower than the current managed version {CurrentVersion}.",
                uri.ToString(), version, source.Version);
        }

        source.Text = text;
        source.Version = version;

        return Task.CompletedTask;
    }

    public Task ApplyIncrementalChange(DocumentUri uri, Range range, string text, int? version)
    {
        var source = this.GetSourceOrThrow(uri);

        _logger.LogDebug("Applying an incremental change to document {Uri} (from {CurrentVersion} to {GotVersion}).",
            uri.ToString(), source.Version, version);

        if (source.Version > version)
        {
            _logger.LogError(
                "Got an incremental change for document {Uri} with version {GotVersion} lower than the current managed version {CurrentVersion}.",
                uri.ToString(), version, source.Version);
        }

        source[range] = text;
        source.Version = version;

        return Task.CompletedTask;
    }

    /// <summary>
    /// Returns a loaded (managed) source from the local store or throws an <see cref="InvalidOperationException"/>
    /// if the document identified by <paramref name="uri"/> is not managed.
    /// </summary>
    private BufferedSource GetSourceOrThrow(DocumentUri uri)
    {
        if (!_managedDocs.TryGetValue(uri, out var source))
        {
            throw new InvalidOperationException("The file is not managed.");
        }

        return source;
    }

    private FileSource GetOrCreateFileSource(DocumentUri uri)
    {
        if (_unmanagedDocs.TryGetValue(uri, out var source))
        {
            return source;
        }

        source = new FileSource(uri, _fileSystem);
        return _unmanagedDocs.GetOrAdd(uri, source);
    }
}
