// StackTraceFeature.cs
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
        public record StackTraceArguments : IRequest<StackTraceResponse>
        {
            /// <summary>
            /// Retrieve the stacktrace for this thread.
            /// </summary>
            public long ThreadId { get; init; }

            /// <summary>
            /// The index of the first frame to return; if omitted frames start at 0.
            /// </summary>
            [Optional]
            public long? StartFrame { get; init; }

            /// <summary>
            /// The maximum number of frames to return. If levels is not specified or 0, all frames are returned.
            /// </summary>
            [Optional]
            public long? Levels { get; init; }

            /// <summary>
            /// Specifies details on how to format the stack frames.
            /// </summary>
            [Optional]
            public StackFrameFormat? Format { get; init; }
        }

        public record StackTraceResponse
        {
            /// <summary>
            /// The frames of the stackframe.If the array has length zero, there are no stackframes available.
            /// This means that there is no location information available.
            /// </summary>
            public Container<StackFrame>? StackFrames { get; init; }

            /// <summary>
            /// The total number of frames available.
            /// </summary>
            [Optional]
            public long? TotalFrames { get; init; }
        }
    }

    namespace Models
    {
        /// <summary>
        /// Provides formatting information for a stack frame.
        /// </summary>
        public record StackFrameFormat : ValueFormat
        {
            /// <summary>
            /// Displays parameters for the stack frame.
            /// </summary>
            [Optional]
            public bool Parameters { get; init; }

            /// <summary>
            /// Displays the types of parameters for the stack frame.
            /// </summary>
            [Optional]
            public bool ParameterTypes { get; init; }

            /// <summary>
            /// Displays the names of parameters for the stack frame.
            /// </summary>
            [Optional]
            public bool ParameterNames { get; init; }

            /// <summary>
            /// Displays the values of parameters for the stack frame.
            /// </summary>
            [Optional]
            public bool ParameterValues { get; init; }

            /// <summary>
            /// Displays the line long of the stack frame.
            /// </summary>
            [Optional]
            public bool Line { get; init; }

            /// <summary>
            /// Displays the module of the stack frame.
            /// </summary>
            [Optional]
            public bool Module { get; init; }

            /// <summary>
            /// Includes all stack frames, including those the debug adapter might otherwise hide.
            /// </summary>
            [Optional]
            public bool IncludeAll { get; init; }
        }
    }
}
