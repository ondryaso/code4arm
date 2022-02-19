// ISourceStore.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Services.Abstractions;

public interface ISourceStore
{
    Task LoadDocument(DocumentUri uri);
    Task<ISource> GetDocument(DocumentUri uri);
    Task CloseDocument(DocumentUri uri);

    Task ApplyFullChange(DocumentUri uri, string text);
    Task ApplyIncrementalChange(DocumentUri uri, Range range, string text);
}
