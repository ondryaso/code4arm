// DummyDocumentationProvider.cs
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

using Code4Arm.LanguageServer.CodeAnalysis.Models;
using Code4Arm.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer.Services;

public class DummyDocumentationProvider : ISymbolDocumentationProvider, IInstructionDocumentationProvider
{
    private readonly ILocalizationService _localizationService;

    public DummyDocumentationProvider(ILocalizationService localizationService)
    {
        _localizationService = localizationService;
    }

    public MarkupContent? this[string key] => _localizationService.TryGetValue(key, out var val)
        ? new MarkupContent { Kind = MarkupKind.Markdown, Value = val! }
        : null;

    public string InstructionDetail(InstructionVariant instructionVariant)
    {
        return instructionVariant.Mnemonic + "instruction";
    }

    public MarkupContent? InstructionEntry(InstructionVariant instructionVariant)
    {
        return new MarkupContent
        {
            Kind = MarkupKind.Markdown,
            Value =
                $"## {instructionVariant.Mnemonic}\nThis is a documentation entry for {instructionVariant.Mnemonic}."
        };
    }

    public MarkupContent? InstructionOperandEntry(InstructionVariant instructionVariant, string tokenName)
    {
        tokenName = tokenName.Replace("<", "&lt;").Replace(">", "&gt;");
        return new MarkupContent
        {
            Kind = MarkupKind.Markdown,
            Value =
                $"## {tokenName}\nThis is a documentation entry for operand {tokenName} of {instructionVariant.Mnemonic}."
        };
    }
}
