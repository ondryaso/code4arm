// RunInTerminalFeature.cs
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
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record RunInTerminalArguments : IRequest<RunInTerminalResponse>
        {
            /// <summary>
            /// What kind of terminal to launch.
            /// </summary>
            [Optional]
            public RunInTerminalArgumentsKind? Kind { get; init; }

            /// <summary>
            /// Optional title of the terminal.
            /// </summary>
            [Optional]
            public string? Title { get; init; }

            /// <summary>
            /// Working directory of the command.
            /// </summary>
            public string Cwd { get; init; }

            /// <summary>
            /// List of arguments.The first argument is the command to run.
            /// </summary>
            public Container<string> Args { get; init; }

            /// <summary>
            /// Environment key-value pairs that are added to or removed from the default environment.
            /// </summary>
            [Optional]
            public IDictionary<string, string>? Env { get; init; }
        }

        public record RunInTerminalResponse
        {
            /// <summary>
            /// The process ID.
            /// </summary>
            [Optional]
            public long? ProcessId { get; init; }

            /// <summary>
            /// The process ID of the terminal shell.
            /// </summary>
            [Optional]
            public long? ShellProcessId { get; init; }
        }

        [JsonConverter(typeof(StringEnumConverter))]
        public enum RunInTerminalArgumentsKind
        {
            Integrated,
            External
        }
    }
}
