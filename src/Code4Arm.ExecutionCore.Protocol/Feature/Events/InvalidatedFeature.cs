using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        public record InvalidatedEvent : IRequest
        {
            /// <summary>
            /// Optional set of logical areas that got invalidated. This property has a
            /// hint characteristic: a client can only be expected to make a 'best
            /// effort' in honouring the areas but there are no guarantees. If this
            /// property is missing, empty, or if values are not understand the client
            /// should assume a single value 'all'.
            /// </summary>
            [Optional]
            public Container<InvalidatedAreas>? Areas { get; init; }

            /// <summary>
            /// If specified, the client only needs to refetch data related to this
            /// thread.
            /// </summary>
            [Optional]
            public int? ThreadId { get; init; }

            /// <summary>
            /// If specified, the client only needs to refetch data related to this stack
            /// frame (and the 'threadId' is ignored).
            /// </summary>
            [Optional]
            public int? StackFrameId { get; init; }
        }
    }
}
