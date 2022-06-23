// BreakpointFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using Code4Arm.ExecutionCore.Protocol.StringEnum;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Models
    {
        /// <summary>
        /// Information about a Breakpoint created in setBreakpoints or setFunctionBreakpoints.
        /// </summary>
        public record Breakpoint
        {
            /// <summary>
            /// An optional identifier for the breakpoint. It is needed if breakpoint events are used to update or remove breakpoints.
            /// </summary>
            [Optional]
            public long? Id { get; init; }

            /// <summary>
            /// If true breakpoint could be set (but not necessarily at the desired location).
            /// </summary>
            public bool Verified { get; init; }

            /// <summary>
            /// An optional message about the state of the breakpoint. This is shown to the user and can be used to explain why a
            /// breakpoint could not be verified.
            /// </summary>
            [Optional]
            public string? Message { get; init; }

            /// <summary>
            /// The source where the breakpoint is located.
            /// </summary>
            [Optional]
            public Source? Source { get; init; }

            /// <summary>
            /// The start line of the actual range covered by the breakpoint.
            /// </summary>
            [Optional]
            public int? Line { get; init; }

            /// <summary>
            /// An optional start column of the actual range covered by the breakpoint.
            /// </summary>
            [Optional]
            public int? Column { get; init; }

            /// <summary>
            /// An optional end line of the actual range covered by the breakpoint.
            /// </summary>
            [Optional]
            public int? EndLine { get; init; }

            /// <summary>
            /// An optional end column of the actual range covered by the breakpoint. If no end line is given, then the end column is
            /// assumed to be in the start line.
            /// </summary>
            [Optional]
            public int? EndColumn { get; init; }

            /// <summary>
            /// An optional memory reference to where the breakpoint is set.
            /// </summary>
            [Optional]
            public string? InstructionReference { get; init; }

            /// <summary>
            /// An optional offset from the instruction reference.
            /// This can be negative.
            /// </summary>
            [Optional]
            public int? Offset { get; init; }
        }
    }

    namespace Events
    {
        [ProtocolEvent(EventNames.Breakpoint)]
        public record BreakpointEvent : IProtocolEvent
        {
            /// <summary>
            /// The reason for the event.
            /// Values: 'changed', 'new', 'removed', etc.
            /// </summary>
            public BreakpointEventReason Reason { get; init; }

            /// <summary>
            /// The 'id' attribute is used to find the target breakpoint and the other attributes are used as the new values.
            /// </summary>
            public Breakpoint Breakpoint { get; init; }
        }

        public class BreakpointEventReason : StringEnum<BreakpointEventReason>
        {
            public static readonly BreakpointEventReason Changed = Create("changed");
            public static readonly BreakpointEventReason New = Create("new");
            public static readonly BreakpointEventReason Removed = Create("removed");
        }
    }
}
