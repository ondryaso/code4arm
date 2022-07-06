// TerminateFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

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
