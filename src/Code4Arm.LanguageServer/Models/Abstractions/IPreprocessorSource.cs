// IPreprocessorSource.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.LanguageServer.Models.Abstractions;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

/// <summary>
/// Represents an <see cref="IPreprocessedSource"/> that handles the preprocessing itself. 
/// </summary>
internal interface IPreprocessorSource : IPreprocessedSource
{
    /// <summary>
    /// Triggers the preprocessing.
    /// </summary>
    /// <param name="modifiedRange">An optional hint with the range in the original document that has been changed.</param>
    Task Preprocess(Range? modifiedRange);
}
