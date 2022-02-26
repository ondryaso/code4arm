// ISourceAnalyser.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models;

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
    /// Requests current analysis for a specific line.
    /// </summary>
    /// <param name="line">Number of the line to analyse.</param>
    /// <returns>An analysis result.</returns>
    Task<AnalysedLine> GetLineAnalysis(int line);
}
