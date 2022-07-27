using Code4Arm.LanguageServer.CodeAnalysis.Models;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

/// <summary>
/// Represents an analyser for directives.
/// </summary>
public interface IDirectiveAnalyser
{
    /// <summary>
    /// Makes a <see cref="AnalysedDirective"/> for the given source text.
    /// </summary>
    /// <param name="directiveText">The source text with a detected directive.</param>
    /// <param name="directiveStartLinePosition">The line index on which the directive starts.</param>
    /// <param name="sourceAnalyser">The parent source analyser.</param>
    /// <returns>An <see cref="AnalysedDirective"/> object with details of the directive and the analysis result.</returns>
    AnalysedDirective AnalyseDirective(string directiveText, int directiveStartLinePosition,
        ISourceAnalyser sourceAnalyser);
}
