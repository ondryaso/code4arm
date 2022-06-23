// Checksum.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Newtonsoft.Json;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// The checksum of an item calculated by the specified algorithm.
/// </summary>
public record Checksum
{
    /// <summary>
    /// The algorithm used to calculate this checksum.
    /// </summary>
    public ChecksumAlgorithm Algorithm { get; init; }

    /// <summary>
    /// Value of the checksum.
    /// </summary>
    [JsonProperty("checksum")]
    public string Value { get; init; }
}
