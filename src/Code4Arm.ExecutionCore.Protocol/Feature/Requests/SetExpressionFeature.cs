// SetExpressionFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

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
