using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        public record TerminatedEvent : IRequest
        {
            /// <summary>
            /// A debug adapter may set 'restart' to true (or to an arbitrary object) to request that the front end restarts the
            /// session.
            /// The value is not interpreted by the client and passed unmodified as an attribute '__restart' to the 'launch' and
            /// 'attach' requests.
            /// </summary>
            [Optional]
            [JsonProperty(PropertyName = "__restart")]
            public JToken? Restart { get; init; }
        }
    }
}
