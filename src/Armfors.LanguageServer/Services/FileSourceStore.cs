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
    private readonly ILoggerFactory _loggerFactory;
    private readonly IFileSystem _fileSystem;

    private readonly ConcurrentDictionary<DocumentUri, BufferedSource> _managedDocs = new();
    private readonly ConcurrentDictionary<DocumentUri, FileSource> _unmanagedDocs = new();

    public FileSourceStore(ILoggerFactory loggerFactory, IFileSystem fileSystem)
    {
        _logger = loggerFactory.CreateLogger<FileSourceStore>();
        _loggerFactory = loggerFactory;
        _fileSystem = fileSystem;
    }

    public async Task LoadDocument(TextDocumentItem document)
    {
        _logger.LogTrace("Loading document {Uri} (announced version: {Version}).", document.Uri, document.Version);

        // First check for existence so that we don't construct a BufferedSource pointlessly
        if (_managedDocs.ContainsKey(document.Uri))
        {
            throw new InvalidOperationException("The file has already been opened.");
        }

        var source = new BufferedSource(document.Uri, document.Version, _loggerFactory)
        {
            Text = document.Text
        };

        await source.PreprocessedSource.Preprocess(null);

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
    }

    public Task<ISource> GetDocument(DocumentUri uri)
    {
        _logger.LogTrace("Document request for {Uri}.", uri);

        if (_managedDocs.TryGetValue(uri, out var source))
        {
            return Task.FromResult(source as ISource);
        }
        else
        {
            return Task.FromResult(this.GetOrCreateFileSource(uri) as ISource);
        }
    }

    public Task<IPreprocessedSource> GetPreprocessedDocument(DocumentUri uri)
    {
        _logger.LogTrace("Preprocessed document request for {Uri}.", uri);

        if (_managedDocs.TryGetValue(uri, out var source))
        {
            return Task.FromResult(source.PreprocessedSource as IPreprocessedSource);
        }

        throw new InvalidOperationException("Preprocessing is currently only available on managed sources.");
    }

    public Task CloseDocument(DocumentUri uri)
    {
        if (!_managedDocs.TryRemove(uri, out var source))
        {
            throw new InvalidOperationException("The file is not opened.");
        }

        source.IsValidRepresentationInternal = false;

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

    public async Task ApplyFullChange(DocumentUri uri, string text, int? version)
    {
        var source = this.GetSourceOrThrow(uri);

        _logger.LogTrace("Applying a full change to document {Uri} (from {CurrentVersion} to {GotVersion}).",
            uri.ToString(), source.Version, version);

        if (source.Version > version)
        {
            _logger.LogError(
                "Got a full change for document {Uri} with version {GotVersion} lower than the current managed version {CurrentVersion}.",
                uri.ToString(), version, source.Version);
        }

        source.Text = text;
        source.VersionInternal = version;

        await source.PreprocessedSource.Preprocess(null);
    }

    public async Task ApplyIncrementalChange(DocumentUri uri, Range range, string text, int? version)
    {
        var source = this.GetSourceOrThrow(uri);

        _logger.LogTrace("Applying an incremental change to document {Uri} (from {CurrentVersion} to {GotVersion}).",
            uri.ToString(), source.Version, version);

        if (source.Version > version)
        {
            _logger.LogError(
                "Got an incremental change for document {Uri} with version {GotVersion} lower than the current managed version {CurrentVersion}.",
                uri.ToString(), version, source.Version);
        }

        source[range] = text;
        source.VersionInternal = version;

        await source.PreprocessedSource.Preprocess(range);
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

        _logger.LogTrace("Creating unmanaged source for {Uri}.", uri);
        source = new FileSource(uri, _fileSystem);
        return _unmanagedDocs.GetOrAdd(uri, source);
    }
}
