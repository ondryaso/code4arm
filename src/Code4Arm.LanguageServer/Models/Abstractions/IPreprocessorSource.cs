// IPreprocessorSource.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.LanguageServer.Models.Abstractions;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

internal interface IPreprocessorSource : IPreprocessedSource
{
    Task Preprocess(Range? modifiedRange);
}
