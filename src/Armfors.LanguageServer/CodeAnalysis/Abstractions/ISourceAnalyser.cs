// ISourceAnalyser.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.CodeAnalysis.Abstractions;

public interface ISourceAnalyser
{
    /// <summary>
    /// Notifies the analyser that a line in the source has changed.
    /// </summary>
    /// <param name="line">Number of the line that has changed.</param>
    /// <param name="added">True if new text was added to the end of the line.</param>
    Task TriggerLineAnalysis(int line, bool added);

    /// <summary>
    /// Start a full analysis.
    /// </summary>
    Task TriggerFullAnalysis();

    /// <summary>
    /// Returns the last analysis result for a specific line.
    /// </summary>
    /// <param name="line">Number of the line to analyse.</param>
    /// <returns>An analysis result or null if such line does not exist..</returns>
    AnalysedLine? GetLineAnalysis(int line);

    /// <summary>
    /// Returns the last analysis results for all lines.
    /// </summary>
    /// <returns>An enumerable of analysis results.</returns>
    IEnumerable<AnalysedLine> GetLineAnalyses();

    /// <summary>
    /// Returns an enumerable of labels found in the last analysis.
    /// </summary>
    /// <returns>An enumerable of <see cref="AnalysedLabel"/> objects with details of labels.</returns>
    IEnumerable<AnalysedLabel> GetLabels();

    /// <summary>
    /// Returns an analysis object for a token on a given position; or null if the position is out of bounds.
    /// </summary>
    /// <param name="position">The position to find token on.</param>
    /// <returns>A token lookup result, or null if the position is out of bounds.</returns>
    AnalysedTokenLookupResult? FindTokenAtPosition(Position position);

    /// <summary>
    /// Returns an <see cref="AnalysedLabel"/> with details of a label.
    /// </summary>
    /// <param name="name">The label.</param>
    /// <returns>An <see cref="AnalysedLabel"/> or null if such label does not exist.</returns>
    AnalysedLabel? GetLabel(string name);

    IEnumerable<AnalysedTokenLookupResult> FindLabelOccurrences(string label, bool includeDefinition);

    IEnumerable<AnalysedTokenLookupResult> FindRegisterOccurrences(Register register);

    IEnumerable<AnalysedFunction> GetFunctions();
}
