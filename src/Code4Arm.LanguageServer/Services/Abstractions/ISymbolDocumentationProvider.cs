// IDocumentationProvider.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer.Services.Abstractions;

/// <summary>
/// Provides documentation for language symbols (like register names or condition codes).  
/// </summary>
public interface ISymbolDocumentationProvider
{
    /// <summary>
    /// Returns documentation for a given key.
    /// </summary>
    /// <param name="key">The documentation key.</param>
    MarkupContent? this[string key] { get; }

    /// <summary>
    /// Returns documentation for a given enum value.
    /// </summary>
    /// <param name="enumValue">The enum value.</param>
    /// <param name="tag">An optional tag determining the context of the enum's usage.
    /// If null, <see cref="ILocalizationService.CompletionDocumentationTag"/> is used.</param>
    /// <typeparam name="T">The enum type.</typeparam>
    MarkupContent? EnumEntry<T>(T enumValue, string? tag = null) where T : struct, Enum
    {
        return this[
            ILocalizationService.GetEnumEntryIdentifier(enumValue,
                tag ?? ILocalizationService.CompletionDocumentationTag)];
    }
}
