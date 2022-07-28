// SetBreakpointsFeature.cs
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
        public record SetBreakpointsArguments : IRequest<SetBreakpointsResponse>
        {
            /// <summary>
            /// The source location of the breakpoints; either 'source.path' or 'source.reference' must be specified.
            /// </summary>
            public Source Source { get; init; }

            /// <summary>
            /// The code locations of the breakpoints.
            /// </summary>
            [Optional]
            public Container<SourceBreakpoint>? Breakpoints { get; init; }

            /// <summary>
            /// Deprecated: The code locations of the breakpoints.
            /// </summary>
            [Obsolete("Deprecated")]
            [Optional]
            public Container<long>? Lines { get; init; }

            /// <summary>
            /// A value of true indicates that the underlying source has been modified which results in new breakpoint locations.
            /// </summary>
            [Optional]
            public bool SourceModified { get; init; }
        }

        public record SetBreakpointsResponse
        {
            /// <summary>
            /// Information about the breakpoints.The array elements are in the same order as the elements of the 'breakpoints' (or the
            /// deprecated 'lines') array in the arguments.
            /// </summary>
            public Container<Breakpoint> Breakpoints { get; init; }
        }
    }
}
