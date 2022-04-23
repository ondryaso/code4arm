// ExceptionInfoFeature.cs
// Original source: https://github.com/OmniSharp/csharp-language-server-protocol
// Original author: David Driscoll (and contributors)
// Edited by: Ondřej Ondryáš
// Licensed under the MIT License. Copyright (c) Ondřej Ondryáš, .NET Foundation and Contributors.

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Serialization;
using MediatR;

// ReSharper disable CheckNamespace
namespace Code4Arm.ExecutionCore.Protocol
{
    namespace Requests
    {
        public record ExceptionInfoArguments : IRequest<ExceptionInfoResponse>
        {
            /// <summary>
            /// Thread for which exception information should be retrieved.
            /// </summary>
            public long ThreadId { get; init; }
        }

        public record ExceptionInfoResponse
        {
            /// <summary>
            /// ID of the exception that was thrown.
            /// </summary>
            public string ExceptionId { get; init; }

            /// <summary>
            /// Descriptive text for the exception provided by the debug adapter.
            /// </summary>
            [Optional]
            public string? Description { get; init; }

            /// <summary>
            /// Mode that caused the exception notification to be raised.
            /// </summary>
            public ExceptionBreakMode BreakMode { get; init; }

            /// <summary>
            /// Detailed information about the exception.
            /// </summary>
            [Optional]
            public ExceptionDetails? Details { get; init; }
        }
    }
}
