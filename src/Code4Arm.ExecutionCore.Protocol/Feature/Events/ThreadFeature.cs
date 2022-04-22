using Code4Arm.ExecutionCore.Protocol.StringEnum;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        public record ThreadEvent : IRequest
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
