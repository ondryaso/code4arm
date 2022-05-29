// ExecutionEngineExceptionHubFilter.cs
// Author: Ondřej Ondryáš

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
            logger.LogWarning(e,
                "Unhandled execution/debugger exception. Connection ID: {Id}. Correlation ID: {Correlation}.",
                invocationContext.Context.ConnectionId, correlationId);
            
            var outputEvent = new OutputEvent()
            {
                Category = OutputEventCategory.Console,
                Output = $"Unexpected execution service error ({e.GetType().Name}). Connection ID: {invocationContext.Context.ConnectionId}. Correlation ID: {correlationId}.",
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
                        Format =
                            "Unexpected execution service error. Connection ID: {connId}. Correlation ID: {corrId}.",
                        Id = ExecutionCore.Execution.Exceptions.ExceptionCodes.UnexpectedErrorId,
                        ShowUser = false,
                        SendTelemetry = true,
                        Variables = new Dictionary<string, string>()
                        {
                            { "connId", invocationContext.Context.ConnectionId },
                            { "corrId", correlationId.ToString() }
                        }
                    }
                }
            };
        }
    }
}
