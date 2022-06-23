// WriteMemoryFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record WriteMemoryArguments : IRequest<WriteMemoryResponse>
        {
            /// <summary>
            /// Memory reference to the base location to which data should be written.
            /// </summary>
            public string MemoryReference { get; init; }

            /// <summary>
            /// Optional offset (in bytes) to be applied to the reference location before writing data. Can be negative.
            /// </summary>
            [Optional]
            public long? Offset { get; init; }

            /// <summary>
            /// Optional property to control partial writes. If true, the debug adapter
            /// should attempt to write memory even if the entire memory region is not
            /// writable. In such a case the debug adapter should stop after hitting the
            /// first byte of memory that cannot be written and return the number of bytes
            /// written in the response via the 'offset' and 'bytesWritten' properties.
            /// If false or missing, a debug adapter should attempt to verify the region is
            /// writable before writing, and fail the response if it is not.
            /// </summary>
            [Optional]
            public bool AllowPartial { get; init; }

            /// <summary>
            /// Bytes to write, encoded using base64.
            /// </summary>
            public string Data { get; init; }
        }

        public record WriteMemoryResponse
        {
            /// <summary>
            /// Optional property that should be returned when 'allowPartial' is true to
            /// indicate the offset of the first byte of data successfully written. Can
            /// be negative.
            /// </summary>
            public long? Offset { get; init; }
            
            /// <summary>
            /// Optional property that should be returned when 'allowPartial' is true to
            /// indicate the number of bytes starting from address that were successfully
            /// written.
            /// </summary>
            public long? BytesWritten { get; init; }
        }
    }
}
