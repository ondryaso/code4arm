using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record ContinueArguments : IRequest<ContinueResponse>
        {
            /// <summary>
            /// Continue execution for the specified thread(if possible). If the backend cannot continue on a single thread but will
            /// continue on all threads, it should set the
            /// 'allThreadsContinued' attribute in the response to true.
            /// </summary>
            public long ThreadId { get; init; }
        }

        public record ContinueResponse
        {
            /// <summary>
            /// If true, the 'continue' request has ignored the specified thread and continued all threads instead.If this attribute is
            /// missing a value of 'true' is assumed for backward
            /// compatibility.
            /// </summary>
            [Optional]
            public bool AllThreadsContinued { get; init; }
        }
    }
}
