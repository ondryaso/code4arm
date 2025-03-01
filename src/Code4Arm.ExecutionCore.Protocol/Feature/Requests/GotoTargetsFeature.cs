// GotoTargetsFeature.cs
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
        public record GotoTargetsArguments : IRequest<GotoTargetsResponse>
        {
            /// <summary>
            /// The source location for which the goto targets are determined.
            /// </summary>
            public Source Source { get; init; }

            /// <summary>
            /// The line location for which the goto targets are determined.
            /// </summary>
            public long Line { get; init; }

            /// <summary>
            /// An optional column location for which the goto targets are determined.
            /// </summary>
            [Optional]
            public long? Column { get; init; }
        }

        public record GotoTargetsResponse
        {
            /// <summary>
            /// The possible goto targets of the specified location.
            /// </summary>
            public Container<GotoTarget> Targets { get; init; }
        }
    }

    namespace Models
    {
        /// <summary>
        /// A GotoTarget describes a code location that can be used as a target in the ‘goto’ request.
        /// The possible goto targets can be determined via the ‘gotoTargets’ request.
        /// </summary>
        public record GotoTarget
        {
            /// <summary>
            /// Unique identifier for a goto target. This is used in the goto request.
            /// </summary>
            public long Id { get; init; }

            /// <summary>
            /// The name of the goto target (shown in the UI).
            /// </summary>
            public string Label { get; init; }

            /// <summary>
            /// The line of the goto target.
            /// </summary>
            public int Line { get; init; }

            /// <summary>
            /// An optional column of the goto target.
            /// </summary>
            [Optional]
            public int? Column { get; init; }

            /// <summary>
            /// An optional end line of the range covered by the goto target.
            /// </summary>
            [Optional]
            public int? EndLine { get; init; }

            /// <summary>
            /// An optional end column of the range covered by the goto target.
            /// </summary>
            [Optional]
            public int? EndColumn { get; init; }

            /// <summary>
            /// Optional memory reference for the instruction pointer value represented by this target.
            /// </summary>
            [Optional]
            public string? InstructionPointerReference { get; init; }
        }
    }
}
