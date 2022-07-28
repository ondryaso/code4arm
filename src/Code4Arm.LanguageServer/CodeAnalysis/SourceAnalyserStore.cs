// SourceAnalyserStore.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

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