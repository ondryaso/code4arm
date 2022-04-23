// LoadedSourcesFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

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
