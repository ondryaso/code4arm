// DataBreakpointInfoFeature.cs
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

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record DataBreakpointInfoArguments : IRequest<DataBreakpointInfoResponse>
        {
            /// <summary>
            /// Reference to the Variable container if the data breakpoint is requested for a child of the container.
            /// </summary>
            [Optional]
            public long? VariablesReference { get; init; }

            /// <summary>
            /// The name of the Variable's child to obtain data breakpoint information for. If variableReference isn’t provided, this
            /// can be an expression.
            /// </summary>
            public string Name { get; init; }
        }

        public record DataBreakpointInfoResponse
        {
            /// <summary>
            /// An identifier for the data on which a data breakpoint can be registered with the setDataBreakpoints request or null if
            /// no data breakpoint is available.
            /// </summary>
            public string? DataId { get; init; }

            /// <summary>
            /// UI string that describes on what data the breakpoint is set on or why a data breakpoint is not available.
            /// </summary>
            public string Description { get; init; }

            /// <summary>
            /// Optional attribute listing the available access types for a potential data breakpoint.A UI frontend could surface this
            /// information.
            /// </summary>
            [Optional]
            public Container<DataBreakpointAccessType>? AccessTypes { get; init; }

            /// <summary>
            /// Optional attribute indicating that a potential data breakpoint could be persisted across sessions.
            /// </summary>
            [Optional]
            public bool CanPersist { get; init; }
        }
    }
}
