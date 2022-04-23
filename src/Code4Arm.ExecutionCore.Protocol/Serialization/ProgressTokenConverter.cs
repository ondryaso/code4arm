// ProgressTokenConverter.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Models;
using Newtonsoft.Json;

namespace Code4Arm.ExecutionCore.Protocol.Serialization;

internal class ProgressTokenConverter : JsonConverter<ProgressToken?>
{
    public override bool CanRead => true;

    public override void WriteJson(JsonWriter writer, ProgressToken? value, JsonSerializer serializer)
    {
        if (value == null) writer.WriteNull();
        else if (value.IsLong) serializer.Serialize(writer, value.Long);
        else if (value.IsString) serializer.Serialize(writer, value.String);
        else writer.WriteNull();
    }

    public override ProgressToken? ReadJson(JsonReader reader, Type objectType, ProgressToken? existingValue,
        bool hasExistingValue, JsonSerializer serializer)
    {
        return reader.TokenType switch
        {
            JsonToken.Integer => new ProgressToken((long) reader.Value),
            JsonToken.String when reader.Value is string str && !string.IsNullOrWhiteSpace(str) =>
                new ProgressToken(str),
            _ => null
        };
    }
}
