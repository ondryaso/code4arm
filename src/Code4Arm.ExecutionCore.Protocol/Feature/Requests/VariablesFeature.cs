// VariablesFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

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
