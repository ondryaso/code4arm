// LaunchFeature.cs
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
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record LaunchRequestArguments : IRequest<LaunchResponse>
        {
            /// <summary>
            /// If noDebug is true the launch request should launch the program without enabling debugging.
            /// </summary>
            [Optional]
            public bool NoDebug { get; init; }

            /// <summary>
            /// Optional data from the previous, restarted session.
            /// The data is sent as the 'restart' attribute of the 'terminated' event.
            /// The client should leave the data intact.
            /// </summary>
            [Optional]
            [JsonProperty(PropertyName = "__restart")]
            public JToken? Restart { get; init; }

            [JsonExtensionData]
            public IDictionary<string, object> ExtensionData { get; init; } = new Dictionary<string, object>();
        }

        public record LaunchResponse
        {
        }
    }
}
