using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        public record ExitedEvent : IRequest
        {
            /// <summary>
            /// The exit code returned from the debuggee.
            /// </summary>
            public long ExitCode { get; init; }
        }
    }
}
