// GotoTargetsFeature.cs
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
        public record GotoTargetsArguments : IRequest<GotoTargetsResponse>
        {
            /// <summary>
            /// The source location for which the goto targets are determined.
            /// </summary>
            public Source Source { get; init; }

            /// <summary>
            /// The line location for which the goto targets are determined.
            /// </summary>
            public long Line { get; init; }

            /// <summary>
            /// An optional column location for which the goto targets are determined.
            /// </summary>
            [Optional]
            public long? Column { get; init; }
        }

        public record GotoTargetsResponse
        {
            /// <summary>
            /// The possible goto targets of the specified location.
            /// </summary>
            public Container<GotoTarget> Targets { get; init; }
        }
    }

    namespace Models
    {
        /// <summary>
        /// A GotoTarget describes a code location that can be used as a target in the ‘goto’ request.
        /// The possible goto targets can be determined via the ‘gotoTargets’ request.
        /// </summary>
        public record GotoTarget
        {
            /// <summary>
            /// Unique identifier for a goto target. This is used in the goto request.
            /// </summary>
            public long Id { get; init; }

            /// <summary>
            /// The name of the goto target (shown in the UI).
            /// </summary>
            public string Label { get; init; }

            /// <summary>
            /// The line of the goto target.
            /// </summary>
            public int Line { get; init; }

            /// <summary>
            /// An optional column of the goto target.
            /// </summary>
            [Optional]
            public int? Column { get; init; }

            /// <summary>
            /// An optional end line of the range covered by the goto target.
            /// </summary>
            [Optional]
            public int? EndLine { get; init; }

            /// <summary>
            /// An optional end column of the range covered by the goto target.
            /// </summary>
            [Optional]
            public int? EndColumn { get; init; }

            /// <summary>
            /// Optional memory reference for the instruction pointer value represented by this target.
            /// </summary>
            [Optional]
            public string? InstructionPointerReference { get; init; }
        }
    }
}
