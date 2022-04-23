// ContinuedFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        public record ContinuedEvent : IRequest
        {
            /// <summary>
            /// The thread which was continued.
            /// </summary>
            public long ThreadId { get; init; }

            /// <summary>
            /// If 'allThreadsContinued' is true, a debug adapter can announce that all threads have continued.
            /// </summary>
            [Optional]
            public bool AllThreadsContinued { get; init; }
        }
    }
}
