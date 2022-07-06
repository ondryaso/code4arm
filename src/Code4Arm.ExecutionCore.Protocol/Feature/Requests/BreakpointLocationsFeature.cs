// BreakpointLocationsFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record BreakpointLocationsArguments : IRequest<BreakpointLocationsResponse>
        {
            /// <summary>
            /// The source location of the breakpoints; either 'source.path' or 'source.reference' must be specified.
            /// </summary>
            public Source Source { get; init; }

            /// <summary>
            /// Start line of range to search possible breakpoint locations in. If only the line is specified, the request returns all
            /// possible locations in that line.
            /// </summary>
            public int Line { get; init; }

            /// <summary>
            /// Optional start column of range to search possible breakpoint locations in. If no start column is given, the first
            /// column in the start line is assumed.
            /// </summary>
            [Optional]
            public int? Column { get; init; }

            /// <summary>
            /// Optional end line of range to search possible breakpoint locations in. If no end line is given, then the end line is
            /// assumed to be the start line.
            /// </summary>
            [Optional]
            public int? EndLine { get; init; }

            /// <summary>
            /// Optional end column of range to search possible breakpoint locations in. If no end column is given, then it is assumed
            /// to be in the last column of the end line.
            /// </summary>
            [Optional]
            public int? EndColumn { get; init; }
        }

        public record BreakpointLocationsResponse
        {
            /// <summary>
            /// Sorted set of possible breakpoint locations.
            /// </summary>
            public Container<BreakpointLocation> Breakpoints { get; init; }
        }
    }

    namespace Models
    {
        public record BreakpointLocation
        {
            /// <summary>
            /// Start line of breakpoint location.
            /// </summary>
            public int Line { get; init; }

            /// <summary>
            /// Optional start column of breakpoint location.
            /// </summary>
            [Optional]
            public int? Column { get; init; }

            /// <summary>
            /// Optional end line of breakpoint location if the location covers a range.
            /// </summary>
            [Optional]
            public int? EndLine { get; init; }

            /// <summary>
            /// Optional end column of breakpoint location if the location covers a range.
            /// </summary>
            [Optional]
            public int? EndColumn { get; init; }
        }
    }
}
