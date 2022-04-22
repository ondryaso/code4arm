using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.StringEnum;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        public record LoadedSourceEvent : IRequest
        {
            /// <summary>
            /// The reason for the event.
            /// </summary>
            public LoadedSourceReason Reason { get; init; }

            /// <summary>
            /// The new, changed, or removed source.
            /// </summary>
            public Source Source { get; init; }
        }

        public class LoadedSourceReason : StringEnum<LoadedSourceReason>
        {
            public static readonly LoadedSourceReason Changed = Create("changed");
            public static readonly LoadedSourceReason New = Create("new");
            public static readonly LoadedSourceReason Removed = Create("removed");
        }
    }
}
