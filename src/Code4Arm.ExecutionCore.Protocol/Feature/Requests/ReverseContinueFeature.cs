using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record ReverseContinueArguments : IRequest<ReverseContinueResponse>
        {
            /// <summary>
            /// Execute 'reverseContinue' for this thread.
            /// </summary>
            public long ThreadId { get; init; }
        }

        public record ReverseContinueResponse
        {
        }
    }
}
