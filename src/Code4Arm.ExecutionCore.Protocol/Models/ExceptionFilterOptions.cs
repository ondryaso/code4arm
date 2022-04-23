// ExceptionFilterOptions.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Serialization;

namespace Code4Arm.ExecutionCore.Protocol.Models;

public record ExceptionFilterOptions
{
    /// <summary>
    /// ID of an exception filter returned by the 'exceptionBreakpointFilters'
    /// capability.
    /// </summary>
    public string FilterId { get; init; }

    /// <summary>
    /// An optional expression for conditional exceptions.
    /// The exception will break into the debugger if the result of the condition
    /// is true.
    /// </summary>
    [Optional]
    public string? Condition { get; init; }
}
