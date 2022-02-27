// IPreprocessedSource.cs
// Author: Ondřej Ondryáš

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Models.Abstractions;

public interface IPreprocessedSource : ISource
{
    ISource BaseSource { get; }
    Range GetOriginalRange(Range preprocessedRange);
    Range GetPreprocessedRange(Range originalRange);
}
