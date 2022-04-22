using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record TerminateArguments : IRequest<TerminateResponse>
        {
            /// <summary>
            /// A value of true indicates that this 'terminate' request is part of a restart sequence.
            /// </summary>
            [Optional]
            public bool Restart { get; init; }
        }

        public record TerminateResponse
        {
        }
    }

    namespace Models
    {
    }
}
