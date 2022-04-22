using Code4Arm.ExecutionCore.Protocol.Models;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record SetDataBreakpointsArguments : IRequest<SetDataBreakpointsResponse>
        {
            /// <summary>
            /// The contents of this array replaces all existing data breakpoints. An empty array clears all data breakpoints.
            /// </summary>
            public Container<DataBreakpoint> Breakpoints { get; init; }
        }

        public record SetDataBreakpointsResponse
        {
            /// <summary>
            /// Information about the data breakpoints.The array elements correspond to the elements of the input argument
            /// 'breakpoints' array.
            /// </summary>
            public Container<Breakpoint> Breakpoints { get; init; }
        }
    }
}
