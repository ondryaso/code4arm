// ModuleFeature.cs
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
        [EventName(EventNames.Module)]
        public record ModuleEvent : IProtocolEvent
        {
            /// <summary>
            /// The reason for the event.
            /// </summary>
            public ModuleEventReason Reason { get; init; }

            /// <summary>
            /// The new, changed, or removed module. In case of 'removed' only the module id is used.
            /// </summary>
            public Module Module { get; init; }
        }

        public class ModuleEventReason : StringEnum<ModuleEventReason>
        {
            public static readonly ModuleEventReason Changed = Create("changed");
            public static readonly ModuleEventReason New = Create("new");
            public static readonly ModuleEventReason Removed = Create("removed");
        }
    }
}
