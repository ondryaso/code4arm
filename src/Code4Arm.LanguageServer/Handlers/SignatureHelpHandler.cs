// SignatureHelpHandler.cs
// Author: Ondřej Ondryáš

using System.Text;
using Code4Arm.LanguageServer.Extensions;
using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using Code4Arm.LanguageServer.CodeAnalysis.Models;
using Code4Arm.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Server;

namespace Code4Arm.LanguageServer.Handlers;

public class SignatureHelpHandler : SignatureHelpHandlerBase
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;
    private readonly IInstructionProvider _instructionProvider;
    private readonly ISymbolDocumentationProvider _symbolDocumentationProvider;
    private readonly IInstructionDocumentationProvider _instructionDocumentationProvider;
    private readonly ILanguageServerConfiguration _configurationContainer;

    public SignatureHelpHandler(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore,
        IInstructionProvider instructionProvider, ISymbolDocumentationProvider symbolDocumentationProvider,
        IInstructionDocumentationProvider instructionDocumentationProvider,
        ILanguageServerConfiguration configurationContainer)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
        _instructionProvider = instructionProvider;
        _symbolDocumentationProvider = symbolDocumentationProvider;
        _instructionDocumentationProvider = instructionDocumentationProvider;
        _configurationContainer = configurationContainer;
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

        var config = await _configurationContainer.GetServerOptions(request);
        var filterFlag = config.Flag;

        var allVariants = await _instructionProvider.GetVariants(lineAnalysis.Mnemonic.Mnemonic);
        if (allVariants is not { Count: > 0 })
            return null;

        allVariants.Sort();
        var currentVariant = 0;
        var ret = new List<SignatureInformation>();

        for (var i = 0; i < allVariants.Count; i++)
        {
            var variant = allVariants[i];

            if (variant.Equals(lineAnalysis.Mnemonic) && !lineAnalysis.MissingOperands)
            {
                var token = analyser.FindTokenAtPosition(prepPosition);
                ret.Add(token is { Type: AnalysedTokenType.OperandToken }
                    ? this.MakeSignatureInformation(variant, lineAnalysis, token.Operand,
                        token.OperandToken!.TokenDescriptor)
                    : this.MakeSignatureInformation(variant));

                currentVariant = i;
            }
            else
            {
                if ((variant.VariantFlags & filterFlag) != 0)
                    continue;

                ret.Add(this.MakeSignatureInformation(variant));
            }
        }

        return new SignatureHelp()
        {
            Signatures = ret,
            ActiveSignature = currentVariant
        };
    }

    private SignatureInformation MakeSignatureInformation(InstructionVariant variant, AnalysedLine? line = null,
        AnalysedOperand? operand = null, OperandTokenDescriptor? toTag = null)
    {
        var paramInfo = new List<ParameterInformation>();
        int? active = null;
        var sb = new StringBuilder();
        var forCurrent = line != null && operand != null;

        sb.Append(variant.Mnemonic);
        sb.Append(' ');

        for (var i = 0; i < variant.Operands.Count; i++)
        {
            var operandDescriptor = variant.Operands[i];
            var hasCustomFormatting = operandDescriptor.HasCustomSignatureFormatting;
            if (hasCustomFormatting)
            {
                sb.Append(forCurrent
                    ? operandDescriptor.GetCustomSignatureFormatting(line!, operand!)
                    : operandDescriptor.GetCustomSignatureFormatting());
            }
            else if (operandDescriptor.Optional && i == 0)
            {
                sb.Append('{');
            }

            var descriptors = forCurrent
                ? operandDescriptor.GetTokenDescriptors(line!, operand!)
                : operandDescriptor.GetTokenDescriptors();

            foreach (var tokenMapping in descriptors)
            {
                if (!hasCustomFormatting)
                {
                    sb.Append($"<{tokenMapping.SymbolicName}>");
                    sb.Append(' ');
                }

                if (toTag == tokenMapping)
                {
                    active = paramInfo.Count;
                }

                paramInfo.Add(new ParameterInformation()
                {
                    Label = new ParameterInformationLabel($"<{tokenMapping.SymbolicName}>"),
                    Documentation =
                        _instructionDocumentationProvider.InstructionOperandEntry(variant,
                            tokenMapping.SymbolicName)
                });
            }

            if (!hasCustomFormatting)
            {
                sb.Length -= 1;
            }

            if (i != variant.Operands.Count - 1)
            {
                if (variant.Operands[i + 1].Optional)
                {
                    sb.Append('{');
                }

                sb.Append(',');
            }

            if (operandDescriptor.Optional && !hasCustomFormatting)
            {
                sb.Append('}');
            }

            sb.Append(' ');
        }

        var si = new SignatureInformation()
        {
            Documentation = _instructionDocumentationProvider.InstructionEntry(variant),
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
