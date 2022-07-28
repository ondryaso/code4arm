// BreakpointFeature.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// 
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// Copyright (c) .NET Foundation and Contributors
// All Rights Reserved
// 
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Available under the MIT License.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
// to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of
// the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
