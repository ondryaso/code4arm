// IDiagnosticsPublisher.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;

namespace Code4Arm.LanguageServer.Services.Abstractions;

public interface IDiagnosticsPublisher
{
    Task PublishAnalysisResult(ISourceAnalyser analyser, DocumentUri documentUri, int? documentVersion);
}
