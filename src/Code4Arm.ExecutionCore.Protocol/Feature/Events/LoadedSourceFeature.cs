// LoadedSourceFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.StringEnum;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        [ProtocolEvent(EventNames.LoadedSource)]
        public record LoadedSourceEvent : IProtocolEvent
        {
            /// <summary>
            /// The reason for the event.
            /// </summary>
            public LoadedSourceReason Reason { get; init; }

            /// <summary>
            /// The new, changed, or removed source.
            /// </summary>
            public Source Source { get; init; }
        }

        public class LoadedSourceReason : StringEnum<LoadedSourceReason>
        {
            public static readonly LoadedSourceReason Changed = Create("changed");
            public static readonly LoadedSourceReason New = Create("new");
            public static readonly LoadedSourceReason Removed = Create("removed");
        }
    }
}
