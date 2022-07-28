// CodeLensHandler.cs
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

using Code4Arm.LanguageServer.Extensions;
using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using Code4Arm.LanguageServer.Services.Abstractions;
using Newtonsoft.Json.Linq;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Server;

namespace Code4Arm.LanguageServer.Handlers;

public class CodeLensHandler : CodeLensHandlerBase
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;
    private readonly ILanguageServerConfiguration _configContainer;

    public CodeLensHandler(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore,
        ILanguageServerConfiguration configContainer)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
        _configContainer = configContainer;
    }

    public override async Task<CodeLensContainer> Handle(CodeLensParams request, CancellationToken cancellationToken)
    {
        var config = await _configContainer.GetServerOptions(request);
        if (!config.ShowCodeLens)
            return new CodeLensContainer();

        var source = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri);
        var analyser = _sourceAnalyserStore.GetAnalyser(source);

        await analyser.TriggerFullAnalysis();

        // Create CodeLens for function labels
        var ret = new List<CodeLens>();
        foreach (var analysedFunction in analyser.GetFunctions())
        {
            if (analysedFunction.TargetAnalysedLabel == null)
                continue;

            var range = source.GetOriginalRange(analysedFunction.TargetAnalysedLabel.Range);

            ret.Add(new CodeLens()
            {
                Range = range,
                Command = new Command
                {
                    Title = $"function, {analysedFunction.TargetAnalysedLabel.ReferencesCount} references",
                    Name = "code4arm.labelAndReferences",
                    Arguments = new JArray(range.Start.Line, range.Start.Character)
                }
            });
        }

        return new CodeLensContainer(ret);
    }

    public override Task<CodeLens> Handle(CodeLens request, CancellationToken cancellationToken)
    {
        return Task.FromResult(request);
    }

    protected override CodeLensRegistrationOptions CreateRegistrationOptions(CodeLensCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new CodeLensRegistrationOptions()
        {
            DocumentSelector = Constants.ArmUalDocumentSelector,
            ResolveProvider = false
        };
    }
}
