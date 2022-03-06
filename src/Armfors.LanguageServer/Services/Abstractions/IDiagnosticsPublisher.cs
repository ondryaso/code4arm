// IDiagnosticsPublisher.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;

namespace Armfors.LanguageServer.Services.Abstractions;

public interface IDiagnosticsPublisher
{
    Task PublishAnalysisResult(ISourceAnalyser analyser, DocumentUri documentUri, int? documentVersion);
}
