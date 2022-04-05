using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.Extensions;
using Armfors.LanguageServer.Services.Abstractions;
using Newtonsoft.Json.Linq;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Server;

namespace Armfors.LanguageServer.Handlers;

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