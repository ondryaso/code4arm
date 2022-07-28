// DisconnectFeature.cs
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
        public record DisconnectArguments : IRequest<DisconnectResponse>
        {
            /// <summary>
            /// A value of true indicates that this 'disconnect' request is part of a restart sequence.
            /// </summary>
            [Optional]
            public bool Restart { get; init; }

            /// <summary>
            /// Indicates whether the debuggee should be terminated when the debugger is disconnected.
            /// If unspecified, the debug adapter is free to do whatever it thinks is best.
            /// A client can only rely on this attribute being properly honored if a debug adapter returns true for the
            /// 'supportTerminateDebuggee' capability.
            /// </summary>
            [Optional]
            public bool TerminateDebuggee { get; init; }

            /// <summary>
            /// Indicates whether the debuggee should stay suspended when the debugger is
            /// disconnected. If unspecified, the debuggee should resume execution.
            /// The attribute is only honored by a debug adapter if the capability
            /// 'supportSuspendDebuggee' is true.
            /// </summary>
            [Optional]
            public bool SuspendDebuggee { get; init; }
        }

        public record DisconnectResponse
        {
        }
    }
}
