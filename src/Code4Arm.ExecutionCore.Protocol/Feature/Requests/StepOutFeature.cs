using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record StepOutArguments : IRequest<StepOutResponse>
        {
            /// <summary>
            /// Execute 'stepOut' for this thread.
            /// </summary>
            public long ThreadId { get; init; }

            /// <summary>
            /// Optional granularity to step. If no granularity is specified, a granularity of 'statement' is assumed.
            /// </summary>
            [Optional]
            public SteppingGranularity? Granularity { get; init; }
        }

        public record StepOutResponse
        {
        }
    }

    namespace Models
    {
    }
}
