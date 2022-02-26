// SourceAnalyser.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Models.Abstractions;
using Microsoft.Extensions.Logging;

namespace Armfors.LanguageServer.CodeAnalysis;

public class SourceAnalyser : ISourceAnalyser
{
    private readonly ISource _source;
    private readonly ILogger<SourceAnalyser> _logger;
    private readonly Dictionary<int, AnalysedLine> _lines = new();

    public ISource Source => _source;

    internal SourceAnalyser(ISource source, ILogger<SourceAnalyser> logger)
    {
        _source = source;
        _logger = logger;
    }

    public Task TriggerLineAnalysis(int line, bool added)
    {
        _logger.LogWarning("Line analysis for {Line}, added: {Added} ({Source}).", line, added, _source.Uri);
        return Task.CompletedTask;
    }

    public Task TriggerFullAnalysis()
    {
        _logger.LogWarning("Full analysis for {Source}", _source.Uri);
        return Task.CompletedTask;
    }

    public Task<AnalysedLine> GetLineAnalysis(int line)
    {
        return Task.FromResult(new AnalysedLine());
    }
}
