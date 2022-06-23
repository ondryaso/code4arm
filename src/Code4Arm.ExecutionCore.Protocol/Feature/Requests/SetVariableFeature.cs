// SetVariableFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record SetVariableArguments : IRequest<SetVariableResponse>
        {
            /// <summary>
            /// The reference of the variable container.
            /// </summary>
            public long VariablesReference { get; init; }

            /// <summary>
            /// The name of the variable in the container.
            /// </summary>
            public string Name { get; init; }

            /// <summary>
            /// The value of the variable.
            /// </summary>
            public string Value { get; init; }

            /// <summary>
            /// Specifies details on how to format the response value.
            /// </summary>
            [Optional]
            public ValueFormat? Format { get; init; }
        }

        public record SetVariableResponse
        {
            /// <summary>
            /// The new value of the variable.
            /// </summary>
            public string Value { get; init; }

            /// <summary>
            /// The type of the new value.Typically shown in the UI when hovering over the value.
            /// </summary>
            [Optional]
            public string? Type { get; init; }

            /// <summary>
            /// If variablesReference is > 0, the new value is structured and its children can be retrieved by passing
            /// variablesReference to the VariablesRequest.
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
