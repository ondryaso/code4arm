// WriteMemoryFeature.cs
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
