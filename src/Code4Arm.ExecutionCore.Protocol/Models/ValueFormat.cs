// ValueFormat.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Serialization;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// Provides formatting information for a value.
/// </summary>
public record ValueFormat
{
    /// <summary>
    /// Display the value in hex.
    /// </summary>
    [Optional]
    public bool Hex { get; init; }
}
