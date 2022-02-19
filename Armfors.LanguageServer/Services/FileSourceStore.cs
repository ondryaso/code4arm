// FileSourceStore.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.Models.Abstractions;
using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Services;

public class FileSourceStore : ISourceStore
{
    public Task LoadDocument(DocumentUri uri)
    {
        throw new NotImplementedException();
    }

    public Task<ISource> GetDocument(DocumentUri uri)
    {
        throw new NotImplementedException();
    }

    public Task CloseDocument(DocumentUri uri)
    {
        throw new NotImplementedException();
    }

    public Task ApplyFullChange(DocumentUri uri, string text)
    {
        throw new NotImplementedException();
    }

    public Task ApplyIncrementalChange(DocumentUri uri, Range range, string text)
    {
        throw new NotImplementedException();
    }
}
