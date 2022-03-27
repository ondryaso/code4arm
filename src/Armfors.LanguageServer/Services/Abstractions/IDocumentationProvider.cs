// IDocumentationProvider.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Services.Abstractions;

public interface IDocumentationProvider
{
    MarkupContent? this[string key] { get; }

    string InstructionDetail(InstructionVariant instructionVariant);
    MarkupContent? InstructionEntry(InstructionVariant instructionVariant);

    MarkupContent? EnumEntry<T>(T enumValue, string? tag = null) where T : struct, Enum
    {
        return this[ILocalizationService.GetEnumEntryIdentifier(enumValue, tag ?? ILocalizationService.CompletionDocumentationTag)];
    }
}
