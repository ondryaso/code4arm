using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record SourceArguments : IRequest<SourceResponse>
        {
            /// <summary>
            /// Specifies the source content to load.Either source.path or source.sourceReference must be specified.
            /// </summary>
            [Optional]
            public Source? Source { get; init; }

            /// <summary>
            /// The reference to the source.This is the same as source.sourceReference.This is provided for backward compatibility
            /// since old backends do not understand the 'source' attribute.
            /// </summary>
            public long SourceReference { get; init; }
        }

        public record SourceResponse
        {
            /// <summary>
            /// Content of the source reference.
            /// </summary>
            public string Content { get; init; }

            /// <summary>
            /// Optional content type(mime type) of the source.
            /// </summary>
            [Optional]
            public string? MimeType { get; init; }
        }
    }

    namespace Models
    {
    }
}
