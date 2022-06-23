// ReverseContinueFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record ReverseContinueArguments : IRequest<ReverseContinueResponse>
        {
            /// <summary>
            /// Execute 'reverseContinue' for this thread.
            /// </summary>
            public long ThreadId { get; init; }
        }

        public record ReverseContinueResponse
        {
        }
    }
}
