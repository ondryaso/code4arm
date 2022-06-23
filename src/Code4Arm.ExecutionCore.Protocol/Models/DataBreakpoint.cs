// DataBreakpoint.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Serialization;

namespace Code4Arm.ExecutionCore.Protocol.Models;

/// <summary>
/// Properties of a data breakpoint passed to the setDataBreakpoints request.
/// </summary>
public record DataBreakpoint
{
    /// <summary>
    /// An id representing the data. This id is returned from the dataBreakpointInfo request.
    /// </summary>
    public string DataId { get; init; }

    /// <summary>
    /// The access type of the data.
    /// </summary>
    [Optional]
    public DataBreakpointAccessType? AccessType { get; init; }

    /// <summary>
    /// An optional expression for conditional breakpoints.
    /// </summary>
    [Optional]
    public string? Condition { get; init; }

    /// <summary>
    /// An optional expression that controls how many hits of the breakpoint are ignored. The backend is expected to interpret
    /// the expression as needed.
    /// </summary>
    [Optional]
    public string? HitCondition { get; init; }
}
