using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record SetBreakpointsArguments : IRequest<SetBreakpointsResponse>
        {
            /// <summary>
            /// The source location of the breakpoints; either 'source.path' or 'source.reference' must be specified.
            /// </summary>
            public Source Source { get; init; }

            /// <summary>
            /// The code locations of the breakpoints.
            /// </summary>
            [Optional]
            public Container<SourceBreakpoint>? Breakpoints { get; init; }

            /// <summary>
            /// Deprecated: The code locations of the breakpoints.
            /// </summary>
            [Obsolete("Deprecated")]
            [Optional]
            public Container<long>? Lines { get; init; }

            /// <summary>
            /// A value of true indicates that the underlying source has been modified which results in new breakpoint locations.
            /// </summary>
            [Optional]
            public bool SourceModified { get; init; }
        }

        public record SetBreakpointsResponse
        {
            /// <summary>
            /// Information about the breakpoints.The array elements are in the same order as the elements of the 'breakpoints' (or the
            /// deprecated 'lines') array in the arguments.
            /// </summary>
            public Container<Breakpoint> Breakpoints { get; init; }
        }
    }
}
