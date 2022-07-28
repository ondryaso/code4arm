// StoppedFeature.cs
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
    namespace Events
    {
        [ProtocolEvent(EventNames.Stopped)]
        public record StoppedEvent : IProtocolEvent
        {
            /// <summary>
            /// The reason for the event.
            /// For backward compatibility this string is shown in the UI if the 'description' attribute is missing (but it must not be
            /// translated).
            /// Values: 'step', 'breakpoint', 'exception', 'pause', 'entry', 'goto', 'function breakpoint', 'data breakpoint', etc.
            /// </summary>
            public StoppedEventReason Reason { get; init; }

            /// <summary>
            /// The full reason for the event, e.g. 'Paused on exception'. This string is shown in the UI as is and must be translated.
            /// </summary>
            [Optional]
            public string? Description { get; init; }

            /// <summary>
            /// The thread which was stopped.
            /// </summary>
            [Optional]
            public long? ThreadId { get; init; }

            /// <summary>
            /// A value of true hints to the frontend that this event should not change the focus.
            /// </summary>
            [Optional]
            public bool PreserveFocusHint { get; init; }

            /// <summary>
            /// Additional information. E.g. if reason is 'exception', text contains the exception name. This string is shown in the
            /// UI.
            /// </summary>
            [Optional]
            public string? Text { get; init; }

            /// <summary>
            /// If 'allThreadsStopped' is true, a debug adapter can announce that all threads have stopped.
            /// - The client should use this information to enable that all threads can be expanded to access their stacktraces.
            /// - If the attribute is missing or false, only the thread with the given threadId can be expanded.
            /// </summary>
            [Optional]
            public bool AllThreadsStopped { get; init; }

            /// <summary>
            /// Ids of the breakpoints that triggered the event. In most cases there will
            /// be only a single breakpoint but here are some examples for multiple
            /// breakpoints:
            /// <list type="bullet">
            /// <item><description>
            ///     Different types of breakpoints map to the same location.
            /// </description></item>
            /// <item><description>
            ///     Multiple source breakpoints get collapsed to the same instruction by the compiler/runtime.
            /// </description></item>
            /// <item><description>
            ///     Multiple function breakpoints with different function names map to the
            ///   same location.
            /// </description></item>
            /// </list>
            /// </summary>
            [Optional]
            public Container<long>? HitBreakpointIds { get; init; }
        }

        public class StoppedEventReason : StringEnum<StoppedEventReason>
        {
            public static readonly StoppedEventReason Step = Create("step");
            public static readonly StoppedEventReason Breakpoint = Create("breakpoint");
            public static readonly StoppedEventReason Exception = Create("exception");
            public static readonly StoppedEventReason Pause = Create("pause");
            public static readonly StoppedEventReason Entry = Create("entry");
            public static readonly StoppedEventReason Goto = Create("goto");

            public static readonly StoppedEventReason FunctionBreakpoint =
                Create("function breakpoint");

            public static readonly StoppedEventReason DataBreakpoint = Create("data breakpoint");

            public static readonly StoppedEventReason InstructionBreakpoint =
                Create("instruction breakpoint");
        }
    }
}
