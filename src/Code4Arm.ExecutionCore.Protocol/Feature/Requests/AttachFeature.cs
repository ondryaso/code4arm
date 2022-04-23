// AttachFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record AttachRequestArguments : IRequest<AttachResponse>
        {
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

        public record AttachResponse
        {
        }
    }
}
