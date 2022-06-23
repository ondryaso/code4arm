// DisconnectFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Modified by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record DisconnectArguments : IRequest<DisconnectResponse>
        {
            /// <summary>
            /// A value of true indicates that this 'disconnect' request is part of a restart sequence.
            /// </summary>
            [Optional]
            public bool Restart { get; init; }

            /// <summary>
            /// Indicates whether the debuggee should be terminated when the debugger is disconnected.
            /// If unspecified, the debug adapter is free to do whatever it thinks is best.
            /// A client can only rely on this attribute being properly honored if a debug adapter returns true for the
            /// 'supportTerminateDebuggee' capability.
            /// </summary>
            [Optional]
            public bool TerminateDebuggee { get; init; }

            /// <summary>
            /// Indicates whether the debuggee should stay suspended when the debugger is
            /// disconnected. If unspecified, the debuggee should resume execution.
            /// The attribute is only honored by a debug adapter if the capability
            /// 'supportSuspendDebuggee' is true.
            /// </summary>
            [Optional]
            public bool SuspendDebuggee { get; init; }
        }

        public record DisconnectResponse
        {
        }
    }
}
