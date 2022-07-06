// TerminateThreadsFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record TerminateThreadsArguments : IRequest<TerminateThreadsResponse>
        {
            /// <summary>
            /// Ids of threads to be terminated.
            /// </summary>
            [Optional]
            public Container<long>? ThreadIds { get; init; }
        }

        public record TerminateThreadsResponse
        {
        }
    }

    namespace Models
    {
    }
}
