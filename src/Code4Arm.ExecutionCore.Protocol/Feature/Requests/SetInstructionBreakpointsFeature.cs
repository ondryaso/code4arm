// SetInstructionBreakpointsFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License, licensing details are available in README.md.
// Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Models;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record SetInstructionBreakpointsArguments : IRequest<SetInstructionBreakpointsResponse>
        {
            /// <summary>
            /// The contents of this array replaces all existing data breakpoints. An empty array clears all data breakpoints.
            /// </summary>
            public Container<InstructionBreakpoint> Breakpoints { get; init; }
        }

        public record SetInstructionBreakpointsResponse
        {
            /// <summary>
            /// Information about the data breakpoints.The array elements correspond to the elements of the input argument
            /// 'breakpoints' array.
            /// </summary>
            public Container<Breakpoint> Breakpoints { get; init; }
        }
    }

    namespace Models
    {
    }
}
