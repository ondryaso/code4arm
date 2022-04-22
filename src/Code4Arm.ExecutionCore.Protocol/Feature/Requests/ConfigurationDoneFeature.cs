using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record ConfigurationDoneArguments : IRequest<ConfigurationDoneResponse>
        {
        }

        public record ConfigurationDoneResponse
        {
        }
    }
}
