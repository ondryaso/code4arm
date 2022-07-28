// Tokenizer.cs
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
using Code4Arm.LanguageServer.Models;
using Code4Arm.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Serilog;

namespace Code4Arm.LanguageServer.Services;

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
            // TODO?
            return;
        }

        var prepSource = await _sourceStore.GetPreprocessedDocument(document);
        var analyser = _sourceAnalyserStore.GetAnalyser(prepSource);
        var modifiers = new List<SemanticTokenModifier>();

        await analyser.TriggerFullAnalysis();
        foreach (var analysis in analyser.GetLineAnalyses())
        {
            foreach (var label in analysis.Labels)
            {
                if (label.Range.Start.Line != analysis.LineIndex)
                    continue;

                builder.Push(prepSource.GetOriginalRange(label.Range), SemanticTokenType.Label,
                    Enumerable.Empty<SemanticTokenModifier>());
            }

            if (analysis.Directive != null)
            {
                builder.Push(prepSource.GetOriginalRange(analysis.Directive.DirectiveRange),
                    ArmSemanticTokenType.Directive, Enumerable.Empty<SemanticTokenModifier>());
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

            /*Log.Warning("P MN [{L}] {O} -> {R}", analysis.LineIndex, analysis.MnemonicRange,
                prepSource.GetOriginalRange(analysis.MnemonicRange!));*/

            builder.Push(prepSource.GetOriginalRange(analysis.MnemonicRange!), ArmSemanticTokenType.Instruction,
                modifiers);

            if (analysis.SetFlagsRange != null)
            {
                //Log.Warning("P SF {R}", prepSource.GetOriginalRange(analysis.SetFlagsRange));
                builder.Push(prepSource.GetOriginalRange(analysis.SetFlagsRange), ArmSemanticTokenType.SetsFlagsFlag,
                    Enumerable.Empty<SemanticTokenModifier>());
            }

            if (analysis.ConditionCodeRange != null)
            {
                //Log.Warning("P CC {R}", prepSource.GetOriginalRange(analysis.ConditionCodeRange));
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
                if (operand.Descriptor == null)
                    continue;

                if (operand.Descriptor.IsSingleToken)
                {
                    var token = operand.Tokens?.FirstOrDefault();

                    if (token == null)
                        continue;

                    var tt = GetOperandSemanticTokenType(token);

                    if (tt == null)
                        continue;

                    builder.Push(prepSource.GetOriginalRange(operand.Range),
                        tt.Value.Type, tt.Value.Modifiers);
                }
                else if (operand.Tokens is { Count: > 0 })
                {
                    foreach (var token in operand.Tokens)
                    {
                        if (token.Result == OperandTokenResult.SyntaxError)
                            continue;

                        var tt = GetOperandSemanticTokenType(token);

                        if (tt == null)
                            continue;

                        builder.Push(prepSource.GetOriginalRange(token.Range),
                            tt.Value.Type, tt.Value.Modifiers);
                    }
                }
            }
        }
    }

    private static (SemanticTokenType Type, IEnumerable<SemanticTokenModifier> Modifiers)? GetOperandSemanticTokenType(
        AnalysedOperandToken token)
    {
        if (token.Type == OperandTokenType.Label && token.Result == OperandTokenResult.UndefinedLabel
            && Constants.SimulatedFunctions.Contains(token.Text))
        {
            return (SemanticTokenType.Label, new[] { ArmSemanticTokenModifier.SimulatedFunction });
        }

        return token.Type switch
        {
            OperandTokenType.Immediate or OperandTokenType.ImmediateConstant or OperandTokenType.ImmediateShift => null,
            OperandTokenType.Register => (ArmSemanticTokenType.Register, Enumerable.Empty<SemanticTokenModifier>()),
            OperandTokenType.SimdRegister => (ArmSemanticTokenType.Register,
                new[] { ArmSemanticTokenModifier.VectorRegister }),
            OperandTokenType.Label => (SemanticTokenType.Label, Enumerable.Empty<SemanticTokenModifier>()),
            OperandTokenType.ShiftType => (ArmSemanticTokenType.ShiftType, Enumerable.Empty<SemanticTokenModifier>()),
            _ => throw new InvalidOperationException()
        };
    }
}
