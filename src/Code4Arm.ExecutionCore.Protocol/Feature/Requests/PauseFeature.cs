using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record PauseArguments : IRequest<PauseResponse>
        {
            /// <summary>
            /// Pause execution for this thread.
            /// </summary>
            public long ThreadId { get; init; }
        }

        public record PauseResponse
        {
        }
    }
}
