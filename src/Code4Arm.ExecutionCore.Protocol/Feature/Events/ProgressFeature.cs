// ProgressFeature.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// 
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// Copyright (c) .NET Foundation and Contributors
// All Rights Reserved
// 
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Available under the MIT License.
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
// documentation files (the "Software"), to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
// to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of
// the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Events
    {
        public abstract record ProgressEvent
        {
            /// <summary>
            /// The ID that was introduced in the initial 'progressStart' event.
            /// </summary>
            public ProgressToken ProgressId { get; init; }

            /// <summary>
            /// Optional, more detailed progress message. If omitted, the previous message (if any) is used.
            /// </summary>
            [Optional]
            public string? Message { get; init; }
        }
        
        [ProtocolEvent(EventNames.ProgressStart)]
        public record ProgressStartEvent : ProgressEvent, IProtocolEvent
        {
            /// <summary>
            /// Mandatory (short) title of the progress reporting. Shown in the UI to describe the long running operation.
            /// </summary>
            public string Title { get; init; }

            /// <summary>
            /// The request ID that this progress report is related to. If specified a debug adapter is expected to emit
            /// progress events for the long running request until the request has been either completed or cancelled.
            /// If the request ID is omitted, the progress report is assumed to be related to some general activity of the debug
            /// adapter.
            /// </summary>
            [Optional]
            public int? RequestId { get; init; }

            /// <summary>
            /// If true, the request that reports progress may be canceled with a 'cancel' request.
            /// So this property basically controls whether the client should use UX that supports cancellation.
            /// Clients that don't support cancellation are allowed to ignore the setting.
            /// </summary>
            [Optional]
            public bool Cancellable { get; init; }

            /// <summary>
            /// Optional progress percentage to display (value range: 0 to 100). If omitted no percentage will be shown.
            /// </summary>
            [Optional]
            public int? Percentage { get; init; }
        }

        [ProtocolEvent(EventNames.ProgressUpdate)]
        public record ProgressUpdateEvent : ProgressEvent, IRequest
        {
            /// <summary>
            /// Optional progress percentage to display (value range: 0 to 100). If omitted no percentage will be shown.
            /// </summary>
            [Optional]
            public double? Percentage { get; init; }
        }

        [ProtocolEvent(EventNames.ProgressEnd)]
        public record ProgressEndEvent : ProgressEvent, IRequest
        {
        }
    }
}
