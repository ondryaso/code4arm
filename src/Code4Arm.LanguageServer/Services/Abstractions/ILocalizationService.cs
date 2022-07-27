// ILocalizationService.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.LanguageServer.Services.Abstractions;

/// <summary>
/// Provides localised strings for the user interface.
/// </summary>
public interface ILocalizationService
{
    public const string CompletionLabelTag = nameof(CompletionLabelTag);
    public const string CompletionLabelSimdTag = nameof(CompletionLabelTag);
    public const string CompletionDescriptionTag = nameof(CompletionDescriptionTag);
    public const string CompletionDescriptionSimdTag = nameof(CompletionDescriptionSimdTag);
    public const string CompletionDocumentationTag = nameof(CompletionDocumentationTag);
    public const string CompletionDocumentationSimdTag = nameof(CompletionDocumentationSimdTag);

    /// <summary>
    /// Returns a localised string for a given key.
    /// </summary>
    /// <param name="entry">The key.</param>
    string this[string entry] { get; }
    
    /// <summary>
    /// Returns a localised string for a given key in a context determined by a tag.
    /// </summary>
    /// <param name="entry">The key.</param>
    /// <param name="tag">The tag.</param>
    string this[string entry, string tag] => this[$"{entry}.{tag}"];
    
    /// <summary>
    /// Returns a localised string for a given key, pluralised for a given number.
    /// </summary>
    /// <param name="entry">The key.</param>
    /// <param name="count">The number.</param>
    string this[string entry, int count] { get; }

    bool HasValue(string entry);
    bool HasValue(string entry, string tag) => this.HasValue($"{entry}.{tag}");
    bool HasValue<T>(T enumValue, string? tag) where T : struct =>
        this.HasValue(GetEnumEntryIdentifier(enumValue, tag));

    bool TryGetValue(string entry, out string? value);
    bool TryGetValue(string entry, string tag, out string? value) => this.TryGetValue($"{entry}.{tag}", out value);
    bool TryGetValue<T>(T enumValue, string? tag, out string? value) where T : struct =>
        this.TryGetValue(GetEnumEntryIdentifier(enumValue, tag), out value);

    public string Format(string entry, params object?[] parameters)
    {
        return string.Format(entry, parameters);
    }

    public string Format(string entry, int count, params object?[] parameters)
    {
        return this.Format(entry, parameters);
    }

    public string EnumEntry<T>(T enumValue, string? tag = null) where T : struct
    {
        return this[GetEnumEntryIdentifier(enumValue, tag)];
    }

    public static string GetEnumEntryIdentifier<T>(T enumValue, string? tag = null) where T : struct
    {
        return $"{typeof(T).Name}.{enumValue.ToString()}.{tag}";
    }
}
