// ReadMemoryFeature.cs
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
        public record ReadMemoryArguments : IRequest<ReadMemoryResponse>
        {
            /// <summary>
            /// Memory reference to the base location from which data should be read.
            /// </summary>
            public string MemoryReference { get; init; }

            /// <summary>
            /// Optional offset(in bytes) to be applied to the reference location before reading data.Can be negative.
            /// </summary>

            [Optional]
            public long? Offset { get; init; }

            /// <summary>
            /// Number of bytes to read at the specified location and offset.
            /// </summary>
            public long Count { get; init; }
        }

        public record ReadMemoryResponse
        {
            /// <summary>
            /// The address of the first byte of data returned.Treated as a hex value if prefixed with '0x', or as a decimal value
            /// otherwise.
            /// </summary>
            public string Address { get; init; }

            /// <summary>
            /// The number of unreadable bytes encountered after the last successfully read byte. This can be used to determine the
            /// number of bytes that must be skipped before a subsequent
            /// 'readMemory' request will succeed.
            /// </summary>
            [Optional]
            public long? UnreadableBytes { get; init; }

            /// <summary>
            /// The bytes read from memory, encoded using base64.
            /// </summary>
            [Optional]
            public string? Data { get; init; }
        }
    }
}
