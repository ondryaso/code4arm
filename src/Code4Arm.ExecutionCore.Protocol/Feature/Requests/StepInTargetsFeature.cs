// StepInTargetsFeature.cs
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
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record StepInTargetsArguments : IRequest<StepInTargetsResponse>
        {
            /// <summary>
            /// The stack frame for which to retrieve the possible stepIn targets.
            /// </summary>
            public long FrameId { get; init; }
        }

        public record StepInTargetsResponse
        {
            /// <summary>
            /// The possible stepIn targets of the specified source location.
            /// </summary>
            public Container<StepInTarget>? Targets { get; init; }
        }
    }

    namespace Models
    {
        /// <summary>
        /// A StepInTarget can be used in the ‘stepIn’ request and determines into which single target the stepIn request should
        /// step.
        /// </summary>
        public record StepInTarget
        {
            /// <summary>
            /// Unique identifier for a stepIn target.
            /// </summary>
            public long Id { get; init; }

            /// <summary>
            /// The name of the stepIn target (shown in the UI).
            /// </summary>
            public string Label { get; init; }
        }
    }
}
