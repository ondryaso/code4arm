// IDocumentationProvider.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.CodeAnalysis.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer.Services.Abstractions;

public interface ISymbolDocumentationProvider
{
    MarkupContent? this[string key] { get; }

    MarkupContent? EnumEntry<T>(T enumValue, string? tag = null) where T : struct, Enum
    {
        return this[
            ILocalizationService.GetEnumEntryIdentifier(enumValue,
                tag ?? ILocalizationService.CompletionDocumentationTag)];
    }
}