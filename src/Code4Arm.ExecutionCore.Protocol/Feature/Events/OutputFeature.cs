// OutputFeature.cs
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
using Code4Arm.ExecutionCore.Protocol.StringEnum;
using MediatR;
using Newtonsoft.Json.Linq;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        [ProtocolEvent(EventNames.Output)]
        public record OutputEvent : IProtocolEvent
        {
            /// <summary>
            /// The output category. If not specified, 'console' is assumed.
            /// Values: 'console', 'stdout', 'stderr', 'telemetry', etc.
            /// </summary>
            [Optional]
            public OutputEventCategory Category { get; init; } = OutputEventCategory.Console;

            /// <summary>
            /// The output to report.
            /// </summary>
            public string Output { get; init; }

            /// <summary>
            /// Support for keeping an output log organized by grouping related messages.
            /// Values:
            /// 'start': Start a new group in expanded mode. Subsequent output events are
            /// members of the group and should be shown indented.
            /// The 'output' attribute becomes the name of the group and is not indented.
            /// 'startCollapsed': Start a new group in collapsed mode. Subsequent output
            /// events are members of the group and should be shown indented (as soon as
            /// the group is expanded).
            /// The 'output' attribute becomes the name of the group and is not indented.
            /// 'end': End the current group and decreases the indentation of subsequent
            /// output events.
            /// A non empty 'output' attribute is shown as the unindented end of the
            /// group.
            /// etc.
            /// </summary>
            [Optional]
            public OutputEventGroup? Group { get; set; }

            /// <summary>
            /// If an attribute 'variablesReference' exists and its value is > 0, the
            /// output contains objects which can be retrieved by passing
            /// 'variablesReference' to the 'variables' request. The value should be less
            /// than or equal to 2147483647 (2^31-1).
            /// </summary>
            [Optional]
            public long? VariablesReference { get; init; }

            /// <summary>
            /// An optional source location where the output was produced.
            /// </summary>
            [Optional]
            public Source? Source { get; init; }

            /// <summary>
            /// An optional source location line where the output was produced.
            /// </summary>
            [Optional]
            public long? Line { get; init; }

            /// <summary>
            /// An optional source location column where the output was produced.
            /// </summary>
            [Optional]
            public long? Column { get; init; }

            /// <summary>
            /// Optional data to report. For the 'telemetry' category the data will be sent to telemetry, for the other categories the
            /// data is shown in JSON format.
            /// </summary>
            [Optional]
            public JToken? Data { get; init; }
        }

        public class OutputEventCategory : StringEnum<OutputEventCategory>
        {
            public static readonly OutputEventCategory Console = Create("console");
            public static readonly OutputEventCategory StandardOutput = Create("stdout");
            public static readonly OutputEventCategory StandardError = Create("stderr");
            public static readonly OutputEventCategory Telemetry = Create("telemetry");
        }

        public class OutputEventGroup : StringEnum<OutputEventGroup>
        {
            public static readonly OutputEventGroup Start = Create("start");
            public static readonly OutputEventGroup StartCollapsed = Create("startCollapsed");
            public static readonly OutputEventGroup End = Create("end");
        }
    }
}
