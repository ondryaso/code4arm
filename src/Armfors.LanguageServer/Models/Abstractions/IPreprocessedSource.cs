// IPreprocessedSource.cs
// Author: Ondřej Ondryáš

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Models.Abstractions;

public interface IPreprocessedSource : ISource
{
    ISource BaseSource { get; }
    Range GetOriginalRange(Range preprocessedRange);
    Range GetPreprocessedRange(Range originalRange);

    int GetOriginalLine(int preprocessedLine)
    {
        return this.GetOriginalRange(new Range(preprocessedLine, 0, preprocessedLine, 0)).Start.Line;
    }

    int GetPreprocessedLine(int originalLine)
    {
        return this.GetPreprocessedRange(new Range(originalLine, 0, originalLine, 0)).Start.Line;
    }
}
