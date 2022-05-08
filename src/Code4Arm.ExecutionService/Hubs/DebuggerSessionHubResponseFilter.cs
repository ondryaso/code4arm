﻿// ExecutionEngineExceptionHubFilter.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionService.Exceptions;
using Microsoft.AspNetCore.SignalR;
using ExecutionEngineException = Code4Arm.ExecutionCore.Execution.Exceptions.ExecutionEngineException;

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
        catch (ExecutionEngineException executionEngineException)
        {
            var logger = _loggerFactory.CreateLogger("Code4Arm.ExecutionCore.Execution");
            logger.LogWarning(executionEngineException,
                "Execution {Id}: {Message}",
                executionEngineException.ExecutionId?.ToString() ?? "unknown", executionEngineException.Message);

            return new DebuggerResponse()
            {
                Success = false,
                Message = executionEngineException.ErrorType,
                Body = new
                {
                    error = this.MakeErrorMessageForException(executionEngineException.ErrorType,
                        executionEngineException.Message)
                }
            };
        }
        catch (DebuggerException debuggerException)
        {
            return new DebuggerResponse()
            {
                Success = false,
                Message = debuggerException.Code,
                Body = new
                {
                    error = new Message()
                    {
                        Format = debuggerException.FullMessageFormat ?? debuggerException.Code,
                        Id = debuggerException.Id,
                        ShowUser = debuggerException.ShowUser,
                        SendTelemetry = debuggerException.SendTelemetry,
                        Variables = debuggerException.Variables,
                    }
                }
            };
        }
    }

    private Message MakeErrorMessageForException(string errorType, string? message)
    {
        // TODO

        return new Message()
        {
            Format = message ?? errorType,
            Id = 0, // TODO
            ShowUser = true,
            SendTelemetry = false
        };
    }
}
