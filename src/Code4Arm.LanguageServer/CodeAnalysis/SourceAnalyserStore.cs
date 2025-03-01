// SourceAnalyserStore.cs
// Author: Ondřej Ondryáš

using System.Collections.Concurrent;
using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using Code4Arm.LanguageServer.Models.Abstractions;
using Code4Arm.LanguageServer.Services.Abstractions;
using Microsoft.Extensions.Logging;
using OmniSharp.Extensions.LanguageServer.Protocol;

namespace Code4Arm.LanguageServer.CodeAnalysis;

public class SourceAnalyserStore : ISourceAnalyserStore
{
    private readonly IInstructionProvider _instructionProvider;
    private readonly IOperandAnalyserProvider _operandAnalyserProvider;
    private readonly IInstructionValidatorProvider _instructionValidatorProvider;
    private readonly IDiagnosticsPublisher _diagnosticsPublisher;
    private readonly IDirectiveAnalyser _directiveAnalyser;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ConcurrentDictionary<DocumentUri, SourceAnalyser> _analysers = new();

    public SourceAnalyserStore(IInstructionProvider instructionProvider,
        IOperandAnalyserProvider operandAnalyserProvider,
        IInstructionValidatorProvider instructionValidatorProvider,
        IDiagnosticsPublisher diagnosticsPublisher,
        IDirectiveAnalyser directiveAnalyser,
        ILoggerFactory loggerFactory)
    {
        _instructionProvider = instructionProvider;
        _operandAnalyserProvider = operandAnalyserProvider;
        _instructionValidatorProvider = instructionValidatorProvider;
        _diagnosticsPublisher = diagnosticsPublisher;
        _directiveAnalyser = directiveAnalyser;
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
            var newAnalyser = new SourceAnalyser(source, _instructionProvider, _operandAnalyserProvider,
                _instructionValidatorProvider, _diagnosticsPublisher, _directiveAnalyser,
                _loggerFactory.CreateLogger<SourceAnalyser>());

            if (!_analysers.TryUpdate(source.Uri, newAnalyser, existing))
            {
                // The analyser in the dictionary has changed in the meantime
                throw new Exception();
            }

            return newAnalyser;
        }
        else
        {
            var newAnalyser = new SourceAnalyser(source, _instructionProvider, _operandAnalyserProvider,
                _instructionValidatorProvider, _diagnosticsPublisher, _directiveAnalyser,
                _loggerFactory.CreateLogger<SourceAnalyser>());

            if (!_analysers.TryAdd(source.Uri, newAnalyser))
            {
                // The analyser in the dictionary has changed in the meantime
                throw new Exception();
            }

            return newAnalyser;
        }
    }
}