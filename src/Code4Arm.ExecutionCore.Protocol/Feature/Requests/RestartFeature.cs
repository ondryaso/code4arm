using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record RestartArguments : IRequest<RestartResponse>
        {
        }

        public record RestartResponse
        {
        }
    }
}
