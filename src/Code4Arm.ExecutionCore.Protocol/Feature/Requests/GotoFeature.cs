// GotoFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record GotoArguments : IRequest<GotoResponse>
        {
            /// <summary>
            /// Set the goto target for this thread.
            /// </summary>
            public long ThreadId { get; init; }

            /// <summary>
            /// The location where the debuggee will continue to run.
            /// </summary>
            public long TargetId { get; init; }
        }

        public record GotoResponse
        {
        }
    }
}
