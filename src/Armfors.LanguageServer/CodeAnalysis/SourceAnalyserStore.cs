// SourceAnalyserStore.cs
// Author: Ondřej Ondryáš

using System.Collections.Concurrent;
using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.Models.Abstractions;
using Microsoft.Extensions.Logging;
using OmniSharp.Extensions.LanguageServer.Protocol;

namespace Armfors.LanguageServer.CodeAnalysis;

public class SourceAnalyserStore : ISourceAnalyserStore
{
    private readonly ILoggerFactory _loggerFactory;
    private readonly ConcurrentDictionary<DocumentUri, SourceAnalyser> _analysers = new();

    public SourceAnalyserStore(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
    }
    
    public ISourceAnalyser GetAnalyser(ISource source)
    {
        if (_analysers.TryGetValue(source.Uri, out var existing))
        {
            if (existing.Source == source && source.IsValidRepresentation)
            {
                return existing;
            }

            // The cached analyser is not using the current version of the source
            var newAnalyser = new SourceAnalyser(source, _loggerFactory.CreateLogger<SourceAnalyser>());
            if (!_analysers.TryUpdate(source.Uri, newAnalyser, existing))
            {
                // The analyser in the dictionary has changed in the meantime
                throw new Exception();
            }

            return newAnalyser;
        }
        else
        {
            var newAnalyser = new SourceAnalyser(source, _loggerFactory.CreateLogger<SourceAnalyser>());
            if (!_analysers.TryAdd(source.Uri, newAnalyser))
            {
                // The analyser in the dictionary has changed in the meantime
                throw new Exception();
            }

            return newAnalyser;
        }
    }
}
