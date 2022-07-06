// NumberStringConverter.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Models;
using Newtonsoft.Json;

namespace Code4Arm.ExecutionCore.Protocol.Serialization;

internal class NumberStringConverter : JsonConverter<NumberString>
{
    public override bool CanRead => true;

    public override void WriteJson(JsonWriter writer, NumberString value, JsonSerializer serializer)
    {
        if (value.IsLong) serializer.Serialize(writer, value.Long);
        else if (value.IsString) serializer.Serialize(writer, value.String);
        else writer.WriteNull();
    }

    public override NumberString ReadJson(JsonReader reader, Type objectType, NumberString existingValue,
        bool hasExistingValue, JsonSerializer serializer)
    {
        if (reader.TokenType == JsonToken.Integer)
            return new NumberString((long) reader.Value);

        if (reader.TokenType == JsonToken.String)
            return new NumberString((string) reader.Value);

        return new NumberString();
    }
}
