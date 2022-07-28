// BreakpointLocationsFeature.cs
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
        public record BreakpointLocationsArguments : IRequest<BreakpointLocationsResponse>
        {
            /// <summary>
            /// The source location of the breakpoints; either 'source.path' or 'source.reference' must be specified.
            /// </summary>
            public Source Source { get; init; }

            /// <summary>
            /// Start line of range to search possible breakpoint locations in. If only the line is specified, the request returns all
            /// possible locations in that line.
            /// </summary>
            public int Line { get; init; }

            /// <summary>
            /// Optional start column of range to search possible breakpoint locations in. If no start column is given, the first
            /// column in the start line is assumed.
            /// </summary>
            [Optional]
            public int? Column { get; init; }

            /// <summary>
            /// Optional end line of range to search possible breakpoint locations in. If no end line is given, then the end line is
            /// assumed to be the start line.
            /// </summary>
            [Optional]
            public int? EndLine { get; init; }

            /// <summary>
            /// Optional end column of range to search possible breakpoint locations in. If no end column is given, then it is assumed
            /// to be in the last column of the end line.
            /// </summary>
            [Optional]
            public int? EndColumn { get; init; }
        }

        public record BreakpointLocationsResponse
        {
            /// <summary>
            /// Sorted set of possible breakpoint locations.
            /// </summary>
            public Container<BreakpointLocation> Breakpoints { get; init; }
        }
    }

    namespace Models
    {
        public record BreakpointLocation
        {
            /// <summary>
            /// Start line of breakpoint location.
            /// </summary>
            public int Line { get; init; }

            /// <summary>
            /// Optional start column of breakpoint location.
            /// </summary>
            [Optional]
            public int? Column { get; init; }

            /// <summary>
            /// Optional end line of breakpoint location if the location covers a range.
            /// </summary>
            [Optional]
            public int? EndLine { get; init; }

            /// <summary>
            /// Optional end column of breakpoint location if the location covers a range.
            /// </summary>
            [Optional]
            public int? EndColumn { get; init; }
        }
    }
}
