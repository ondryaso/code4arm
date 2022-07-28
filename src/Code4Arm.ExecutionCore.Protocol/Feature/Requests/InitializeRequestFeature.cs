// InitializeRequestFeature.cs
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

using System.Text.Json.Serialization;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;
using Newtonsoft.Json;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record InitializeRequestArguments : IRequest<InitializeResponse>, IInitializeRequestArguments
        {
            /// <summary>
            /// The ID of the(frontend) client using this adapter.
            /// </summary>

            [Optional]
            [JsonProperty("clientID")]
            [JsonPropertyName("clientID")]
            public string? ClientId { get; set; }

            /// <summary>
            /// The human readable name of the(frontend) client using this adapter.
            /// </summary>

            [Optional]
            public string? ClientName { get; set; }

            /// <summary>
            /// The ID of the debug adapter.
            /// </summary>
            [JsonProperty("adapterID")]
            [JsonPropertyName("adapterID")]
            public string AdapterId { get; set; } = null!;

            /// <summary>
            /// The ISO-639 locale of the(frontend) client using this adapter, e.g.en-US or de-CH.
            /// </summary>

            [Optional]
            public string? Locale { get; set; }

            /// <summary>
            /// If true all line numbers are 1-based(default).
            /// </summary>
            [Optional]
            public bool LinesStartAt1 { get; set; }

            /// <summary>
            /// If true all column numbers are 1-based(default).
            /// </summary>
            [Optional]
            public bool ColumnsStartAt1 { get; set; }

            /// <summary>
            /// Determines in what format paths are specified.The default is 'path', which is the native format.
            /// Values: 'path', 'uri', etc.
            /// </summary>
            [Optional]
            public PathFormat? PathFormat { get; set; }

            /// <summary>
            /// Client supports the optional type attribute for variables.
            /// </summary>
            [Optional]
            public bool SupportsVariableType { get; set; }

            /// <summary>
            /// Client supports the paging of variables.
            /// </summary>
            [Optional]
            public bool SupportsVariablePaging { get; set; }

            /// <summary>
            /// Client supports the runInTerminal request.
            /// </summary>
            [Optional]
            public bool SupportsRunInTerminalRequest { get; set; }

            /// <summary>
            /// Client supports memory references.
            /// </summary>
            [Optional]
            public bool SupportsMemoryReferences { get; set; }

            /// <summary>
            /// Client supports progress reporting.
            /// </summary>
            [Optional]
            public bool SupportsProgressReporting { get; set; }

            /// <summary>
            /// Client supports the invalidated event.
            /// </summary>
            [Optional]
            public bool SupportsInvalidatedEvent { get; set; }
            
            /// <summary>
            /// Client supports the memory event.
            /// </summary>
            [Optional]
            public bool SupportsMemoryEvent { get; set; }
        }

        public record InitializeResponse : Capabilities
        {
        }
    }
}
