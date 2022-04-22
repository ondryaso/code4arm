// MemoryFeature.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Protocol.Models;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        public record MemoryEvent : IRequest
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
