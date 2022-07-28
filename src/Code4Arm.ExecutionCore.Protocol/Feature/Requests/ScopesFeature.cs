// ScopesFeature.cs
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
        public record ScopesArguments : IRequest<ScopesResponse>
        {
            /// <summary>
            /// Retrieve the scopes for this stackframe.
            /// </summary>
            public long FrameId { get; init; }
        }

        public record ScopesResponse
        {
            /// <summary>
            /// The scopes of the stackframe.If the array has length zero, there are no scopes available.
            /// </summary>
            public Container<Scope> Scopes { get; init; }
        }
    }

    namespace Models
    {
        /// <summary>
        /// A Scope is a named container for variables.Optionally a scope can map to a source or a range within a source.
        /// </summary>
        public record Scope
        {
            /// <summary>
            /// Name of the scope such as 'Arguments', 'Locals', or 'Registers'. This string is shown in the UI as is and can be
            /// translated.
            /// </summary>
            public string Name { get; init; }

            /// <summary>
            /// An optional hint for how to present this scope in the UI. If this attribute is missing, the scope is shown with a
            /// generic UI.
            /// Values:
            /// 'arguments': Scope contains method arguments.
            /// 'locals': Scope contains local variables.
            /// 'registers': Scope contains registers. Only a single 'registers' scope should be returned from a 'scopes' request.
            /// etc.
            /// </summary>
            [Optional]
            public string? PresentationHint { get; init; }

            /// <summary>
            /// The variables of this scope can be retrieved by passing the value of variablesReference to the VariablesRequest.
            /// </summary>
            public long VariablesReference { get; init; }

            /// <summary>
            /// The long of named variables in this scope.
            /// The client can use this optional information to present the variables in a paged UI and fetch them in chunks.
            /// </summary>
            [Optional]
            public long? NamedVariables { get; init; }

            /// <summary>
            /// The long of indexed variables in this scope.
            /// The client can use this optional information to present the variables in a paged UI and fetch them in chunks.
            /// </summary>
            [Optional]
            public long? IndexedVariables { get; init; }

            /// <summary>
            /// If true, the long of variables in this scope is large or expensive to retrieve.
            /// </summary>
            public bool Expensive { get; init; }

            /// <summary>
            /// Optional source for this scope.
            /// </summary>
            [Optional]
            public Source? Source { get; init; }

            /// <summary>
            /// Optional start line of the range covered by this scope.
            /// </summary>
            [Optional]
            public int? Line { get; init; }

            /// <summary>
            /// Optional start column of the range covered by this scope.
            /// </summary>
            [Optional]
            public int? Column { get; init; }

            /// <summary>
            /// Optional end line of the range covered by this scope.
            /// </summary>
            [Optional]
            public int? EndLine { get; init; }

            /// <summary>
            /// Optional end column of the range covered by this scope.
            /// </summary>
            [Optional]
            public int? EndColumn { get; init; }
        }
    }
}
