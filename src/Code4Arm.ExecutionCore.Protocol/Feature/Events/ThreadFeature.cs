// ThreadFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.StringEnum;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        [EventName(EventNames.Thread)]
        public record ThreadEvent : IProtocolEvent
        {
            /// <summary>
            /// The reason for the event.
            /// Values: 'started', 'exited', etc.
            /// </summary>
            public ThreadEventReason Reason { get; init; }

            /// <summary>
            /// The identifier of the thread.
            /// </summary>
            public long ThreadId { get; init; }
        }

        public class ThreadEventReason : StringEnum<ThreadEventReason>
        {
            public static readonly ThreadEventReason Started = Create("started");
            public static readonly ThreadEventReason Exited = Create("exited");
        }
    }
}
