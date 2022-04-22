using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        /// <summary>
        /// DAP is kind of silly....
        /// Cancellation is for requests and progress tokens... hopefully if isn't ever expanded any further... because that would
        /// be fun.
        /// </summary>
        public record CancelArguments : IRequest<CancelResponse>
        {
            // This is removed on purpose, as request cancellation is handled by the DapReciever
            // /// <summary>
            // /// The ID (attribute 'seq') of the request to cancel. If missing no request is cancelled.
            // /// Both a 'requestId' and a 'progressId' can be specified in one request.
            // /// </summary>
            // [Optional]
            // public int? RequestId { get; set; }

            /// <summary>
            /// The ID (attribute 'progressId') of the progress to cancel. If missing no progress is cancelled.
            /// Both a 'requestId' and a 'progressId' can be specified in one request.
            /// </summary>
            [Optional]
            public ProgressToken? ProgressId { get; init; }
        }

        public record CancelResponse
        {
            /// <summary>
            /// The ID (attribute 'seq') of the request to cancel. If missing no request is cancelled.
            /// Both a 'requestId' and a 'progressId' can be specified in one request.
            /// </summary>
            [Optional]
            public int? RequestId { get; init; }

            /// <summary>
            /// The ID (attribute 'progressId') of the progress to cancel. If missing no progress is cancelled.
            /// Both a 'requestId' and a 'progressId' can be specified in one request.
            /// </summary>
            [Optional]
            public ProgressToken? ProgressId { get; init; }
        }
    }
}
