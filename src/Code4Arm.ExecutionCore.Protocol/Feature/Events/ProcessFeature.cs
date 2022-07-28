// ProcessFeature.cs
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
using Code4Arm.ExecutionCore.Protocol.StringEnum;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        [ProtocolEvent(EventNames.Process)]
        public record ProcessEvent : IProtocolEvent
        {
            /// <summary>
            /// The logical name of the process. This is usually the full path to process's executable file. Example:
            /// /home/example/myproj/program.js.
            /// </summary>
            public string Name { get; init; }

            /// <summary>
            /// The system process id of the debugged process. This property will be missing for non-system processes.
            /// </summary>
            [Optional]
            public long? SystemProcessId { get; init; }

            /// <summary>
            /// If true, the process is running on the same computer as the debug adapter.
            /// </summary>
            [Optional]
            public bool IsLocalProcess { get; init; }

            /// <summary>
            /// Describes how the debug engine started debugging this process.
            /// 'launch': Process was launched under the debugger.
            /// 'attach': Debugger attached to an existing process.
            /// 'attachForSuspendedLaunch': A project launcher component has launched a new process in a suspended state and then asked
            /// the debugger to attach.
            /// </summary>
            [Optional]
            public ProcessEventStartMethod? StartMethod { get; init; }

            /// <summary>
            /// The size of a pointer or address for this process, in bits. This value may be used by clients when formatting addresses
            /// for display.
            /// </summary>
            [Optional]
            public long? PointerSize { get; init; }
        }

        public class ProcessEventStartMethod : StringEnum<ProcessEventStartMethod>
        {
            public static readonly ProcessEventStartMethod Launch = Create("launch");
            public static readonly ProcessEventStartMethod Attach = Create("attach");

            public static readonly ProcessEventStartMethod AttachForSuspendedLaunch =
                Create("attachForSuspendedLaunch");
        }
    }
}
