// DataBreakpointInfoFeature.cs
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
        public record DataBreakpointInfoArguments : IRequest<DataBreakpointInfoResponse>
        {
            /// <summary>
            /// Reference to the Variable container if the data breakpoint is requested for a child of the container.
            /// </summary>
            [Optional]
            public long? VariablesReference { get; init; }

            /// <summary>
            /// The name of the Variable's child to obtain data breakpoint information for. If variableReference isn’t provided, this
            /// can be an expression.
            /// </summary>
            public string Name { get; init; }
        }

        public record DataBreakpointInfoResponse
        {
            /// <summary>
            /// An identifier for the data on which a data breakpoint can be registered with the setDataBreakpoints request or null if
            /// no data breakpoint is available.
            /// </summary>
            public string? DataId { get; init; }

            /// <summary>
            /// UI string that describes on what data the breakpoint is set on or why a data breakpoint is not available.
            /// </summary>
            public string Description { get; init; }

            /// <summary>
            /// Optional attribute listing the available access types for a potential data breakpoint.A UI frontend could surface this
            /// information.
            /// </summary>
            [Optional]
            public Container<DataBreakpointAccessType>? AccessTypes { get; init; }

            /// <summary>
            /// Optional attribute indicating that a potential data breakpoint could be persisted across sessions.
            /// </summary>
            [Optional]
            public bool CanPersist { get; init; }
        }
    }
}
