// DummyDocumentationProvider.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Services.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Services;

public class DummyDocumentationProvider : IDocumentationProvider
{
    private readonly ILocalizationService _localizationService;

    public DummyDocumentationProvider(ILocalizationService localizationService)
    {
        _localizationService = localizationService;
    }

    public MarkupContent? this[string key] => _localizationService.TryGetValue(key, out var val)
        ? new MarkupContent { Kind = MarkupKind.Markdown, Value = val! }
        : new MarkupContent { Kind = MarkupKind.Markdown, Value = $"### {key} docstring" };

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
}
