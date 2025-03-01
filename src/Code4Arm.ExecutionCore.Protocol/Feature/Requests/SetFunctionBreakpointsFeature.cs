// SetFunctionBreakpointsFeature.cs
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
        public record SetFunctionBreakpointsArguments : IRequest<SetFunctionBreakpointsResponse>
        {
            /// <summary>
            /// The function names of the breakpoints.
            /// </summary>
            public Container<FunctionBreakpoint> Breakpoints { get; init; }
        }

        public record SetFunctionBreakpointsResponse
        {
            /// <summary>
            /// Information about the breakpoints.The array elements correspond to the elements of the 'breakpoints' array.
            /// </summary>
            public Container<Breakpoint> Breakpoints { get; init; }
        }
    }

    namespace Models
    {
        /// <summary>
        /// FunctionBreakpoint
        /// Properties of a breakpoint passed to the setFunctionBreakpoints request.
        /// </summary>
        public record FunctionBreakpoint
        {
            /// <summary>
            /// The name of the function.
            /// </summary>
            public string Name { get; init; }

            /// <summary>
            /// An optional expression for conditional breakpoints.
            /// </summary>
            [Optional]
            public string? Condition { get; init; }

            /// <summary>
            /// An optional expression that controls how many hits of the breakpoint are ignored. The backend is expected to interpret
            /// the expression as needed.
            /// </summary>
            [Optional]
            public string? HitCondition { get; init; }
        }
    }
}
