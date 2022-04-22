using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record RestartArguments : IRequest<RestartResponse>
        {
            /// <summary>
            /// The latest version of the 'launch' or 'attach' configuration.
            /// </summary>
            [Optional]
            public LaunchRequestArguments? Arguments { get; init; }
        }

        public record RestartResponse
        {
        }
    }
}
