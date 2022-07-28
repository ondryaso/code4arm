// SemanticTokensHandler.cs
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
using Code4Arm.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Client.Capabilities;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer.Handlers;

public class SemanticTokensHandler : SemanticTokensHandlerBase
{
    private readonly ITokenizer _tokenizer;

    private static readonly SemanticTokenType[] UsedTokenTypes = new[]
    {
        ArmSemanticTokenType.Instruction, ArmSemanticTokenType.Directive, ArmSemanticTokenType.Register,
        ArmSemanticTokenType.ConditionCode, ArmSemanticTokenType.SetsFlagsFlag, ArmSemanticTokenType.VectorDataType,
        ArmSemanticTokenType.InstructionSizeQualifier, SemanticTokenType.Label, SemanticTokenType.Method
    };

    private static readonly SemanticTokenModifier[] UsedTokenModifiers = new[]
    {
        ArmSemanticTokenModifier.Conditional, ArmSemanticTokenModifier.SetsFlags,
        ArmSemanticTokenModifier.VectorInstruction
    };

    private readonly ConcurrentDictionary<DocumentUri, SemanticTokensDocument> _semanticTokensDocuments = new();

    public SemanticTokensHandler(ITokenizer tokenizer)
    {
        _tokenizer = tokenizer;
    }

    protected override async Task Tokenize(SemanticTokensBuilder builder, ITextDocumentIdentifierParams identifier,
        CancellationToken cancellationToken)
    {
        await _tokenizer.Tokenize(identifier.TextDocument.Uri, builder);
    }

    protected override Task<SemanticTokensDocument> GetSemanticTokensDocument(ITextDocumentIdentifierParams @params,
        CancellationToken cancellationToken)
    {
        /*var document = _semanticTokensDocuments.GetOrAdd(@params.TextDocument.Uri,
            _ => new SemanticTokensDocument(this.RegistrationOptions));*/
        return Task.FromResult(new SemanticTokensDocument(this.RegistrationOptions));
    }

    protected override SemanticTokensRegistrationOptions CreateRegistrationOptions(SemanticTokensCapability capability,
        ClientCapabilities clientCapabilities)
    {
        return new SemanticTokensRegistrationOptions()
        {
            Full = new SemanticTokensCapabilityRequestFull() { Delta = true },
            Range = true,
            DocumentSelector = Constants.ArmUalDocumentSelector,
            Legend = new SemanticTokensLegend()
            {
                TokenTypes = new Container<SemanticTokenType>(UsedTokenTypes),
                TokenModifiers = new Container<SemanticTokenModifier>(UsedTokenModifiers)
            }
        };
    }
}
