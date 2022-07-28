// IDiagnosticsPublisher.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;

namespace Code4Arm.LanguageServer.Services.Abstractions;

/// <summary>
/// Used to determine and push diagnostics (errors, warnings etc.) after finishing code analysis. 
/// </summary>
public interface IDiagnosticsPublisher
{
    /// <summary>
    /// Determines the diagnostics based on the state of a given <see cref="ISourceAnalyser"/> and sends them to the client.
    /// </summary>
    Task PublishAnalysisResult(ISourceAnalyser analyser, DocumentUri documentUri, int? documentVersion);

    /// <summary>
    /// Clears the shown diagnostics for a given file.
    /// </summary>
    Task ClearDiagnostics(DocumentUri documentUri, int? documentVersion);
}
