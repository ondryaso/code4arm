using Code4Arm.ExecutionCore.Protocol.Models;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record LoadedSourcesArguments : IRequest<LoadedSourcesResponse>
        {
        }

        public record LoadedSourcesResponse
        {
            /// <summary>
            /// Set of loaded sources.
            /// </summary>
            public Container<Source> Sources { get; init; }
        }
    }

    namespace Models
    {
    }
}
