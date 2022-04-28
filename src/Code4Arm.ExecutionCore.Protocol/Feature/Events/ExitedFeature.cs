// ExitedFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        [EventName(EventNames.Exited)]
        public record ExitedEvent : IProtocolEvent
        {
            /// <summary>
            /// The exit code returned from the debuggee.
            /// </summary>
            public long ExitCode { get; init; }
        }
    }
}
