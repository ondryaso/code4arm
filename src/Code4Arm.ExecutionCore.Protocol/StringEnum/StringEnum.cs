﻿// StringEnum.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

#nullable disable

using System.Reflection;
using System.Runtime.CompilerServices;
using Newtonsoft.Json;

namespace Code4Arm.ExecutionCore.Protocol.StringEnum;

/// <remarks>Version with Newtonsoft.Json support.</remarks>
/// <summary>
/// Base class for creating string-valued enums in .NET.<br/>
/// Provides static Parse() and TryParse() methods and implicit cast to string.
/// </summary>
/// <example>
///     <code>
/// class Color : StringEnum &lt;Color&gt;
/// {
///     public static readonly Color Blue = Create("Blue");
///     public static readonly Color Red = Create("Red");
///     public static readonly Color Green = Create("Green");
/// }
/// </code>
/// </example>
/// <typeparam name="T">The string-valued enum type. (i.e. class Color : StringEnum&lt;Color&gt;)</typeparam>
[JsonConverter(typeof(StringEnumJsonConverter))]
public abstract class StringEnum<T> : IEquatable<T> where T : StringEnum<T>, new()
{
    private static readonly Dictionary<string, T> valueDict = new();
    protected string Value;
    bool IEquatable<T>.Equals(T other) => Value.Equals(other.Value);

    protected static T Create(string value)
    {
        if (value == null)
            return null; // the null-valued instance is null.

        var result = new T {Value = value};
        valueDict.Add(value, result);

        return result;
    }

    public static implicit operator string(StringEnum<T> enumValue) => enumValue.Value;
    public override string ToString() => Value;

    public static bool operator !=(StringEnum<T> o1, StringEnum<T> o2) => o1?.Value != o2?.Value;
    public static bool operator ==(StringEnum<T> o1, StringEnum<T> o2) => o1?.Value == o2?.Value;

    public override bool Equals(object other) => Value.Equals((other as T)?.Value ?? other as string);
    public override int GetHashCode() => Value.GetHashCode();

    /// <summary>
    /// Parse the <paramref name="value"/> specified and returns a valid <typeparamref name="T"/> or else throws
    /// InvalidOperationException.
    /// </summary>
    /// <param name="value">
    /// The string value representad by an instance of <typeparamref name="T"/>. Matches by string value,
    /// not by the member name.
    /// </param>
    /// <param name="caseSensitive">
    /// If true, the strings must match case and takes O(log n). False allows different case but is
    /// little bit slower (O(n))
    /// </param>
    public static T Parse(string value, bool caseSensitive = true)
    {
        var result = TryParse(value, caseSensitive);

        if (result == null)
            throw new InvalidOperationException((value == null ? "null" : $"'{value}'") +
                $" is not a valid {typeof(T).Name}");

        return result;
    }

    /// <summary>
    /// Parse the <paramref name="value"/> specified and returns a valid <typeparamref name="T"/> or else returns null.
    /// </summary>
    /// <param name="value">
    /// The string value representad by an instance of <typeparamref name="T"/>. Matches by string value,
    /// not by the member name.
    /// </param>
    /// <param name="caseSensitive">If true, the strings must match case. False allows different case but is slower: O(n)</param>
    public static T TryParse(string value, bool caseSensitive = true)
    {
        if (value == null) return null;
        if (valueDict.Count == 0)
            RuntimeHelpers
                .RunClassConstructor(typeof(T).TypeHandle); // force static fields initialization
        if (caseSensitive)
        {
            if (valueDict.TryGetValue(value, out var item))
                return item;

            return null;
        }

        // slower O(n) case insensitive search
        return valueDict.FirstOrDefault(f => f.Key.Equals(value, StringComparison.OrdinalIgnoreCase)).Value;
        // Why Ordinal? => https://esmithy.net/2007/10/15/why-stringcomparisonordinal-is-usually-the-right-choice/
    }
}

public class StringEnumJsonConverter : JsonConverter
{
    public override bool CanConvert(Type objectType) => IsSubclassOfRawGeneric(typeof(StringEnum<>), objectType);

    public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
    {
        writer.WriteValue(value.ToString());
    }

    public override object ReadJson(JsonReader reader, Type objectType, object existingValue,
        JsonSerializer serializer)
    {
        var s = (string) reader.Value;

        return typeof(StringEnum<>)
               .MakeGenericType(objectType)
               .GetMethod("Parse", BindingFlags.Public | BindingFlags.Static)
               ?.Invoke(null, new object[] {s, false});
        ;
    }

    private static bool IsSubclassOfRawGeneric(Type generic, Type toCheck)
    {
        while ((toCheck != null) && (toCheck != typeof(object)))
        {
            var cur = toCheck.IsGenericType ? toCheck.GetGenericTypeDefinition() : toCheck;

            if (generic == cur)
                return true;

            toCheck = toCheck.BaseType;
        }

        return false;
    }
}

#nullable restore
