// Thread.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// A Thread
/// </summary>
public record Thread
{
    /// <summary>
    /// Unique identifier for the thread.
    /// </summary>
    public long Id { get; init; }

    /// <summary>
    /// A name of the thread.
    /// </summary>
    public string Name { get; init; }
}
