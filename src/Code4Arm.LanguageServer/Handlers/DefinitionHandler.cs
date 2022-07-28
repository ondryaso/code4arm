// DefinitionHandler.cs
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
using Code4Arm.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer.Handlers;

public class DefinitionHandler : DefinitionHandlerBase
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;

    public DefinitionHandler(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
    }

    public override async Task<LocationOrLocationLinks> Handle(DefinitionParams request,
        CancellationToken cancellationToken)
    {
        var source = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri);
        var analyser = _sourceAnalyserStore.GetAnalyser(source);

        await analyser.TriggerFullAnalysis();

        var prepPosition = source.GetPreprocessedPosition(request.Position);
        var token = analyser.FindTokenAtPosition(prepPosition);
        if (token == null)
            return new LocationOrLocationLinks();

        string? label = null;

        if (token.Type == AnalysedTokenType.OperandToken)
        {
            var operandToken = token.OperandToken!;
            if (operandToken.Type == OperandTokenType.Label && operandToken.Data.TargetLabel != null)
            {
                label = operandToken.Data.TargetLabel.Label;
            }
        }

        if (token.Type == AnalysedTokenType.Label)
        {
            label = token.Label!.Label;
        }

        if (label != null)
        {
            var sourceLabel = analyser.GetLabel(label);
            if (sourceLabel == null)
                return new LocationOrLocationLinks(); // TODO: log

            return new LocationOrLocationLinks(new Location()
            {
                Range = source.GetOriginalRange(sourceLabel.Range),
                Uri = request.TextDocument.Uri
            });
        }

        return new LocationOrLocationLinks();
    }

    protected override DefinitionRegistrationOptions CreateRegistrationOptions(DefinitionCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new DefinitionRegistrationOptions()
        {
            DocumentSelector = Constants.ArmUalDocumentSelector
        };
    }
}
