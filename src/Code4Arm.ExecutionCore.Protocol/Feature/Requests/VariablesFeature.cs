// VariablesFeature.cs
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
        public record VariablesArguments : IRequest<VariablesResponse>
        {
            /// <summary>
            /// The Variable reference.
            /// </summary>
            public long VariablesReference { get; init; }

            /// <summary>
            /// Optional filter to limit the child variables to either named or indexed.If ommited, both types are fetched.
            /// </summary>
            [Optional]
            public VariablesArgumentsFilter? Filter { get; init; }

            /// <summary>
            /// The index of the first variable to return; if omitted children start at 0.
            /// </summary>
            [Optional]
            public long? Start { get; init; }

            /// <summary>
            /// The number of variables to return. If count is missing or 0, all variables are returned.
            /// </summary>
            [Optional]
            public long? Count { get; init; }

            /// <summary>
            /// Specifies details on how to format the Variable values.
            /// </summary>
            [Optional]
            public ValueFormat? Format { get; init; }
        }

        public record VariablesResponse
        {
            /// <summary>
            /// All(or a range) of variables for the given variable reference.
            /// </summary>
            public Container<Variable>? Variables { get; init; }
        }

        [JsonConverter(typeof(StringEnumConverter))]
        public enum VariablesArgumentsFilter
        {
            Indexed,
            Named
        }
    }
}
