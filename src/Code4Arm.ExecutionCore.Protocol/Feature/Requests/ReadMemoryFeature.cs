// ReadMemoryFeature.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// 
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// Copyright (c) .NET Foundation and Contributors
// All Rights Reserved
// 
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Available under the MIT License.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
// to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of
// the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
