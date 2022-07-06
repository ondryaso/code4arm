// MemoryFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Models;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        [ProtocolEvent(EventNames.Memory)]
        public record MemoryEvent : IProtocolEvent
        {
            /// <summary>
            /// Memory reference of a memory range that has been updated.
            /// </summary>
            public string MemoryReference { get; init; }

            /// <summary>
            /// Starting offset in bytes where memory has been updated. Can be negative.
            /// </summary>
            public long Offset { get; init; }

            /// <summary>
            /// Number of bytes updated.
            /// </summary>
            public long Count { get; init; }
        }
    }
}
