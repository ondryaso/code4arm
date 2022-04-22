using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record TerminateThreadsArguments : IRequest<TerminateThreadsResponse>
        {
            /// <summary>
            /// Ids of threads to be terminated.
            /// </summary>
            [Optional]
            public Container<long>? ThreadIds { get; init; }
        }

        public record TerminateThreadsResponse
        {
        }
    }

    namespace Models
    {
    }
}
