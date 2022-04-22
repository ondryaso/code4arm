using Code4Arm.ExecutionCore.Protocol.Models;
using MediatR;
using Thread = Code4Arm.ExecutionCore.Protocol.Models.Thread;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record ThreadsArguments : IRequest<ThreadsResponse>
        {
        }

        public record ThreadsResponse
        {
            /// <summary>
            /// All threads.
            /// </summary>
            public Container<Thread>? Threads { get; init; }
        }
    }
}
