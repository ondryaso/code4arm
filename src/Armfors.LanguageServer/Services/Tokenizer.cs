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

        Log.Warning("Builder HC: {Hc}", builder.GetHashCode());

        await analyser.TriggerFullAnalysis();
        foreach (var analysis in analyser.GetLineAnalyses())
        {
            foreach (var label in analysis.Labels)
            {
                if (label.Range.Start.Line != analysis.LineIndex)
                    continue;

                Log.Warning("P LAB {R}", prepSource.GetOriginalRange(label.Range));
                builder.Push(prepSource.GetOriginalRange(label.Range), SemanticTokenType.Label,
                    Enumerable.Empty<SemanticTokenModifier>());
            }

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

            Log.Warning("P MN [{L}] {O} -> {R}", analysis.LineIndex, analysis.MnemonicRange,
                prepSource.GetOriginalRange(analysis.MnemonicRange!));

            builder.Push(prepSource.GetOriginalRange(analysis.MnemonicRange!), ArmSemanticTokenType.Instruction,
                modifiers);

            if (analysis.SetFlagsRange != null)
            {
                Log.Warning("P SF {R}", prepSource.GetOriginalRange(analysis.SetFlagsRange));
                builder.Push(prepSource.GetOriginalRange(analysis.SetFlagsRange), ArmSemanticTokenType.SetsFlagsFlag,
                    Enumerable.Empty<SemanticTokenModifier>());
            }

            if (analysis.ConditionCodeRange != null)
            {
                Log.Warning("P CC {R}", prepSource.GetOriginalRange(analysis.ConditionCodeRange));
                builder.Push(prepSource.GetOriginalRange(analysis.ConditionCodeRange),
                    ArmSemanticTokenType.ConditionCode,
                    Enumerable.Empty<SemanticTokenModifier>());
            }

            foreach (var specifier in analysis.Specifiers)
            {
                if (specifier.IsComplete)
                {
                    builder.Push(prepSource.GetOriginalRange(specifier.Range),
                        specifier.IsInstructionSizeQualifier
                            ? ArmSemanticTokenType.InstructionSizeQualifier
                            : ArmSemanticTokenType.VectorDataType,
                        Enumerable.Empty<SemanticTokenModifier>());
                }
            }

            if (analysis.Operands == null)
                continue;
            
            foreach (var operand in analysis.Operands)
            {
                if (operand.Result != OperandResult.Valid)
                    continue;
                    
                if (operand.Descriptor.SingleTokenType.HasValue)
                {
                    var tt = GetOperandSemanticTokenType(operand.Descriptor.SingleTokenType.Value);
                    if (tt == null)
                        continue;

                    builder.Push(prepSource.GetOriginalRange(operand.Range),
                        tt.Value.Type, tt.Value.Modifiers);
                }
                else if (operand.Tokens != null)
                {
                    foreach (var (operandTokenType, range) in operand.Tokens)
                    {
                        var tt = GetOperandSemanticTokenType(operandTokenType);
                        if (tt == null)
                            continue;

                        builder.Push(prepSource.GetOriginalRange(range),
                            tt.Value.Type, tt.Value.Modifiers);
                    }
                }
            }
        }
    }

    private static (SemanticTokenType Type, IEnumerable<SemanticTokenModifier> Modifiers)? GetOperandSemanticTokenType(
        OperandTokenType tokenType)
    {
        return tokenType switch
        {
            OperandTokenType.Immediate => null,
            OperandTokenType.Register => (ArmSemanticTokenType.Register, Enumerable.Empty<SemanticTokenModifier>()),
            OperandTokenType.SimdRegister => (ArmSemanticTokenType.Register,
                new[] { ArmSemanticTokenModifier.VectorRegister }),
            OperandTokenType.Label => (SemanticTokenType.Label, Enumerable.Empty<SemanticTokenModifier>()),
            OperandTokenType.ShiftType => (ArmSemanticTokenType.ShiftType, Enumerable.Empty<SemanticTokenModifier>()),
            _ => throw new ArgumentOutOfRangeException(nameof(tokenType), tokenType, null)
        };
    }
}
