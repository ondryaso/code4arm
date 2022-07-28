// SetExpressionFeature.cs
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
        public record SetExpressionArguments : IRequest<SetExpressionResponse>
        {
            /// <summary>
            /// The l-value expression to assign to.
            /// </summary>
            public string Expression { get; init; }

            /// <summary>
            /// The value expression to assign to the l-value expression.
            /// </summary>
            public string Value { get; init; }

            /// <summary>
            /// Evaluate the expressions in the scope of this stack frame. If not specified, the expressions are evaluated in the
            /// global scope.
            /// </summary>
            [Optional]
            public long? FrameId { get; init; }

            /// <summary>
            /// Specifies how the resulting value should be formatted.
            /// </summary>
            [Optional]
            public ValueFormat? Format { get; init; }
        }

        public record SetExpressionResponse
        {
            /// <summary>
            /// The new value of the expression.
            /// </summary>
            public string Value { get; init; }

            /// <summary>
            /// The optional type of the value.
            /// </summary>
            [Optional]
            public string? Type { get; init; }

            /// <summary>
            /// Properties of a value that can be used to determine how to render the result in the UI.
            /// </summary>
            [Optional]
            public VariablePresentationHint? PresentationHint { get; init; }

            /// <summary>
            /// If variablesReference is > 0, the value is structured and its children can be retrieved by passing variablesReference
            /// to the VariablesRequest.
            /// </summary>
            [Optional]
            public long? VariablesReference { get; init; }

            /// <summary>
            /// The number of named child variables.
            /// The client can use this optional information to present the variables in a paged UI and fetch them in chunks.
            /// </summary>
            [Optional]
            public long? NamedVariables { get; init; }

            /// <summary>
            /// The number of indexed child variables.
            /// The client can use this optional information to present the variables in a paged UI and fetch them in chunks.
            /// </summary>
            [Optional]
            public long? IndexedVariables { get; init; }
        }
    }
}
