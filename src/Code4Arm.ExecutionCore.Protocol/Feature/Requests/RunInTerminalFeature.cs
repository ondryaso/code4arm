// RunInTerminalFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

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
