// ISourceAnalyserStore.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.Models.Abstractions;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

/// <summary>
/// Provides source analyser instances for sources.
/// </summary>
public interface ISourceAnalyserStore
{
    /// <summary>
    /// Returns an analyser for a given source.
    /// </summary>
    ISourceAnalyser GetAnalyser(ISource source);
}
