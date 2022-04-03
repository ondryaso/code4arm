// SignatureHelpHandler.cs
// Author: Ondřej Ondryáš

using System.Text;
using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Handlers;

public class SignatureHelpHandler : SignatureHelpHandlerBase
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;
    private readonly IInstructionProvider _instructionProvider;
    private readonly IDocumentationProvider _documentationProvider;

    public SignatureHelpHandler(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore,
        IInstructionProvider instructionProvider, IDocumentationProvider documentationProvider)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
        _instructionProvider = instructionProvider;
        _documentationProvider = documentationProvider;
    }

    public override async Task<SignatureHelp?> Handle(SignatureHelpParams request, CancellationToken cancellationToken)
    {
        var source = await _sourceStore.GetPreprocessedDocument(request.TextDocument.Uri);
        var analyser = _sourceAnalyserStore.GetAnalyser(source);
        var prepPosition = source.GetPreprocessedPosition(request.Position);

        await analyser.TriggerLineAnalysis(prepPosition.Line, false);

        var lineAnalysis = analyser.GetLineAnalysis(prepPosition.Line);
        if (lineAnalysis == null)
        {
            return null;
        }

        if (lineAnalysis.PreFinishState != LineAnalysisState.MnemonicLoaded
            || lineAnalysis.Mnemonic is not { HasOperands: true })
        {
            return null;
        }

        var allVariants = await _instructionProvider.GetVariants(lineAnalysis.Mnemonic.Mnemonic);
        // TODO: filter
        allVariants.Sort();
        var currentVariant = 0;
        var ret = new List<SignatureInformation>();

        for (var i = 0; i < allVariants.Count; i++)
        {
            var variant = allVariants[i];

            if (variant.Equals(lineAnalysis.Mnemonic))
            {
                var token = analyser.FindTokenAtPosition(prepPosition);
                ret.Add(token is { Type: AnalysedTokenType.OperandToken }
                    ? this.MakeSignatureInformation(variant, token.OperandToken!.Token)
                    : this.MakeSignatureInformation(variant));

                currentVariant = i;
            }
            else
            {
                ret.Add(this.MakeSignatureInformation(variant));
            }
        }

        return new SignatureHelp()
        {
            Signatures = ret,
            ActiveSignature = currentVariant
        };
    }

    private SignatureInformation MakeSignatureInformation(InstructionVariant variant, OperandToken? toTag = null)
    {
        var paramInfo = new List<ParameterInformation>();
        int? active = null;
        var sb = new StringBuilder();

        sb.Append(variant.Mnemonic);
        sb.Append(' ');

        for (var i = 0; i < variant.Operands.Count; i++)
        {
            var operandDescriptor = variant.Operands[i];
            var hasCustomFormatting = operandDescriptor.TokenFormatting != null;
            if (hasCustomFormatting)
            {
                sb.Append(string.Format(operandDescriptor.TokenFormatting!, operandDescriptor.MatchGroupsTokenMappings
                    .SelectMany(t => t.Value)
                    .Select(t => t.Value.SymbolicName as object).ToArray()));
            }

            foreach (var tokenMapping in operandDescriptor.MatchGroupsTokenMappings.SelectMany(t => t.Value))
            {
                if (!hasCustomFormatting)
                {
                    sb.Append(tokenMapping.Value.SymbolicName);
                    sb.Append(' ');
                }

                if (toTag == tokenMapping.Value)
                {
                    active = paramInfo.Count;
                }

                paramInfo.Add(new ParameterInformation()
                {
                    Label = new ParameterInformationLabel(tokenMapping.Value.SymbolicName),
                    Documentation =
                        _documentationProvider.InstructionOperandEntry(variant, tokenMapping.Value.SymbolicName)
                });
            }

            if (!hasCustomFormatting)
            {
                sb.Length -= 1;
            }

            if (i != variant.Operands.Count - 1)
            {
                sb.Append(", ");
            }
        }

        var si = new SignatureInformation()
        {
            Documentation = _documentationProvider.InstructionEntry(variant),
            Label = sb.ToString(),
            ActiveParameter = active ?? int.MaxValue,
            Parameters = paramInfo
        };

        return si;
    }

    protected override SignatureHelpRegistrationOptions CreateRegistrationOptions(SignatureHelpCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new SignatureHelpRegistrationOptions()
        {
            TriggerCharacters = new Container<string>(",", " "),
            DocumentSelector = Constants.ArmUalDocumentSelector
        };
    }
}
