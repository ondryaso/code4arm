// SymbolReferencesHandler.cs
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

using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using Code4Arm.LanguageServer.CodeAnalysis.Models;
using Code4Arm.LanguageServer.Models.Abstractions;
using Code4Arm.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer.Handlers;

public class SymbolReferencesHandler : ReferencesHandlerBase
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;

    public SymbolReferencesHandler(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
    }

    public override async Task<LocationContainer> Handle(ReferenceParams request, CancellationToken cancellationToken)
    {
        var source = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri);
        var analyser = _sourceAnalyserStore.GetAnalyser(source);
        var prepPosition = source.GetPreprocessedPosition(request.Position);
        
        await analyser.TriggerFullAnalysis();

        var token = analyser.FindTokenAtPosition(prepPosition);
        if (token == null)
            return new LocationContainer();

        // Labels & registers
        if (token.Type == AnalysedTokenType.OperandToken)
        {
            var operandToken = token.OperandToken!;
            if (operandToken.Type == OperandTokenType.Label)
            {
                var targetLabel = operandToken.Data.TargetLabel;
                if (targetLabel == null)
                    return new LocationContainer();

                return MakeLocationsForLabel(request, analyser, source, targetLabel);
            }

            if (operandToken.Type == OperandTokenType.Register)
            {
                var targetRegister = operandToken.Data.Register;
                return MakeLocationsForRegister(request, analyser, source, targetRegister);
            }
        }
        else if (token.Type == AnalysedTokenType.Label)
        {
            return MakeLocationsForLabel(request, analyser, source, token.Label!);
        }

        return new LocationContainer();
    }

    private static LocationContainer MakeLocationsForLabel(ReferenceParams request, ISourceAnalyser analyser,
        IPreprocessedSource source, AnalysedLabel targetLabel)
    {
        var usages = analyser.FindLabelOccurrences(targetLabel.Label, request.Context.IncludeDeclaration);
        return new LocationContainer(usages.Select(u => new Location()
        {
            Range = source.GetOriginalRange(u.TokenRange),
            Uri = request.TextDocument.Uri
        }));
    }

    private static LocationContainer MakeLocationsForRegister(ReferenceParams request, ISourceAnalyser analyser,
        IPreprocessedSource source, Register targetRegister)
    {
        var usages = analyser.FindRegisterOccurrences(targetRegister);
        return new LocationContainer(usages.Select(u => new Location()
        {
            Range = source.GetOriginalRange(u.TokenRange),
            Uri = request.TextDocument.Uri
        }));
    }

    protected override ReferenceRegistrationOptions CreateRegistrationOptions(ReferenceCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new ReferenceRegistrationOptions()
        {
            DocumentSelector = Constants.ArmUalDocumentSelector
        };
    }
}
