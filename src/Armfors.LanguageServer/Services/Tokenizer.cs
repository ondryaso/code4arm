// Tokenizer.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Models;
using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Serilog;

namespace Armfors.LanguageServer.Services;

public class Tokenizer : ITokenizer
{
    private readonly ISourceStore _sourceStore;
    private readonly ISourceAnalyserStore _sourceAnalyserStore;

    public Tokenizer(ISourceStore sourceStore, ISourceAnalyserStore sourceAnalyserStore)
    {
        _sourceStore = sourceStore;
        _sourceAnalyserStore = sourceAnalyserStore;
    }

    public async Task Tokenize(DocumentUri document, SemanticTokensBuilder builder)
    {
        var source = await _sourceStore.GetDocument(document);
        if (source is not BufferedSource)
        {
            // TODO
            return;
        }

        var prepSource = await _sourceStore.GetPreprocessedDocument(document);
        var analyser = _sourceAnalyserStore.GetAnalyser(prepSource);
        var modifiers = new List<SemanticTokenModifier>();

        await analyser.TriggerFullAnalysis();
        foreach (var analysis in analyser.GetLineAnalyses())
        {
            if (!analysis.HasMnemonicMatch)
            {
                continue;
            }

            modifiers.Clear();

            if (analysis.IsConditional)
            {
                modifiers.Add(ArmSemanticTokenModifier.Conditional);
            }

            if (analysis.SetsFlags)
            {
                modifiers.Add(ArmSemanticTokenModifier.SetsFlags);
            }

            if (analysis.Mnemonic!.IsVector)
            {
                modifiers.Add(ArmSemanticTokenModifier.VectorInstruction);
            }

            Log.Warning("P MN {R}", analysis.MnemonicRange);
            builder.Push(analysis.MnemonicRange!, ArmSemanticTokenType.Instruction, modifiers);

            if (analysis.SetFlagsRange != null)
            {
                Log.Warning("P SF {R}", analysis.SetFlagsRange);
                builder.Push(analysis.SetFlagsRange, ArmSemanticTokenType.SetsFlagsFlag,
                    Enumerable.Empty<SemanticTokenModifier>());
            }

            if (analysis.ConditionCodeRange != null)
            {
                Log.Warning("P CC {R}", analysis.ConditionCodeRange);
                builder.Push(analysis.ConditionCodeRange, ArmSemanticTokenType.ConditionCode,
                    Enumerable.Empty<SemanticTokenModifier>());
            }

            foreach (var specifier in analysis.Specifiers)
            {
                if (specifier.IsComplete)
                {
                    builder.Push(specifier.Range,
                        specifier.IsInstructionSizeQualifier
                            ? ArmSemanticTokenType.InstructionSizeQualifier
                            : ArmSemanticTokenType.VectorDataType,
                        Enumerable.Empty<SemanticTokenModifier>());
                }
            }
        }
    }
}
