// EvaluateFeature.cs
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

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record EvaluateArguments : IRequest<EvaluateResponse>
        {
            /// <summary>
            /// The expression to evaluate.
            /// </summary>
            public string Expression { get; init; }

            /// <summary>
            /// Evaluate the expression in the scope of this stack frame. If not specified, the expression is evaluated in the global
            /// scope.
            /// </summary>
            [Optional]
            public long? FrameId { get; init; }

            /// <summary>
            /// The context in which the evaluate request is run.
            /// Values:
            /// 'watch': evaluate is run in a watch.
            /// 'repl': evaluate is run from REPL console.
            /// 'hover': evaluate is run from a data hover.
            /// etc.
            /// </summary>
            [Optional]
            public EvaluateArgumentsContext? Context { get; init; }

            /// <summary>
            /// Specifies details on how to format the Evaluate result.
            /// </summary>
            [Optional]
            public ValueFormat? Format { get; init; }
        }

        public class EvaluateArgumentsContext : StringEnum<EvaluateArgumentsContext>
        {
            public static readonly EvaluateArgumentsContext Variables = Create("variables");
            public static readonly EvaluateArgumentsContext Watch = Create("watch");
            public static readonly EvaluateArgumentsContext Repl = Create("repl");
            public static readonly EvaluateArgumentsContext Hover = Create("hover");
            public static readonly EvaluateArgumentsContext Clipboard = Create("clipboard");
        }

        public record EvaluateResponse
        {
            /// <summary>
            /// The result of the evaluate request.
            /// </summary>
            public string Result { get; init; }

            /// <summary>
            /// The optional type of the evaluate result.
            /// </summary>
            [Optional]
            public string? Type { get; init; }

            /// <summary>
            /// Properties of a evaluate result that can be used to determine how to render the result in the UI.
            /// </summary>
            [Optional]
            public VariablePresentationHint? PresentationHint { get; init; }

            /// <summary>
            /// If variablesReference is > 0, the evaluate result is structured and its children can be retrieved by passing
            /// variablesReference to the VariablesRequest.
            /// </summary>
            public long VariablesReference { get; init; }

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

            /// <summary>
            /// Memory reference to a location appropriate for this result.For pointer type eval results, this is generally a reference
            /// to the memory address contained in the pointer.
            /// </summary>
            [Optional]
            public string? MemoryReference { get; init; }
        }
    }
}
