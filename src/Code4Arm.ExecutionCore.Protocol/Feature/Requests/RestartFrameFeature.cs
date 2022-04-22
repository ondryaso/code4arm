using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record RestartFrameArguments : IRequest<RestartFrameResponse>
        {
            /// <summary>
            /// Restart this stackframe.
            /// </summary>
            public long FrameId { get; init; }
        }

        public record RestartFrameResponse
        {
        }
    }
}
