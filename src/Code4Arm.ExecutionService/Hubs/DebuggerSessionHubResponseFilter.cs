// DebuggerSessionHubResponseFilter.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionCore.Protocol.Events;
using Code4Arm.ExecutionCore.Protocol.Models;
using Microsoft.AspNetCore.SignalR;

namespace Code4Arm.ExecutionService.Hubs;

public class DebuggerSessionHubResponseFilter : IHubFilter
{
    public class DebuggerResponse
    {
        public bool Success { get; init; }
        public string? Message { get; init; }
        public object? Body { get; init; }
    }

    private readonly ILoggerFactory _loggerFactory;

    public DebuggerSessionHubResponseFilter(ILoggerFactory loggerFactory)
    {
        _loggerFactory = loggerFactory;
    }

    public async ValueTask<object?> InvokeMethodAsync(HubInvocationContext invocationContext,
        Func<HubInvocationContext, ValueTask<object?>> next)
    {
        try
        {
            var body = await next(invocationContext);

            return new DebuggerResponse() { Success = true, Body = body };
        }
        catch (DebuggerException debuggerException)
        {
            var message = new Message()
            {
                Format = debuggerException.Message,
                Id = debuggerException.ErrorId,
                ShowUser = debuggerException.ErrorType == DebuggerExceptionType.User
            };

            if (debuggerException.ErrorType == DebuggerExceptionType.Log)
            {
                var outputEvent = new OutputEvent()
                {
                    Category = OutputEventCategory.Console,
                    Output = debuggerException.Message,
                };

                await invocationContext.Hub.Clients.Caller.SendCoreAsync("HandleEvent",
                    new object[] { EventNames.Output, outputEvent });
            }

            return new DebuggerResponse()
            {
                Success = false,
                Message = debuggerException.ErrorMessage,
                Body = new
                {
                    error = message
                }
            };
        }
        catch (Exception e)
        {
            var logger = _loggerFactory.CreateLogger(invocationContext.Hub.GetType());
            var correlationId = Guid.NewGuid();

#if REMOTE
            logger.LogWarning(e,
                "Unhandled execution/debugger exception. Connection ID: {Id}. Correlation ID: {Correlation}.",
                invocationContext.Context.ConnectionId, correlationId);
#else
            logger.LogWarning(e, "Unhandled execution/debugger exception.");
#endif

            var outputEvent = new OutputEvent()
            {
                Category = OutputEventCategory.Console,
#if REMOTE
                Output =
                    $"Unexpected execution service error ({e.GetType().Name}). Connection ID: {invocationContext.Context.ConnectionId}. Correlation ID: {correlationId}."
#else
                Output = $"Unexpected execution service error ({e.GetType().Name})."
#endif
            };

            await invocationContext.Hub.Clients.Caller.SendCoreAsync("HandleEvent",
                new object[] { EventNames.Output, outputEvent });

            return new DebuggerResponse()
            {
                Success = false,
                Message = ExecutionCore.Execution.Exceptions.ExceptionCodes.UnexpectedError,
                Body = new
                {
                    error = new Message()
                    {
#if REMOTE
                        Format =
                            "Unexpected execution service error. Connection ID: {connId}. Correlation ID: {corrId}.",
                        Variables = new Dictionary<string, string>()
                        {
                            { "connId", invocationContext.Context.ConnectionId },
                            { "corrId", correlationId.ToString() }
                        },
#else
                        Format = "Unexpected execution service error.",
#endif
                        Id = ExecutionCore.Execution.Exceptions.ExceptionCodes.UnexpectedErrorId,
                        ShowUser = false,
                        SendTelemetry = true
                    }
                }
            };
        }
    }
}
