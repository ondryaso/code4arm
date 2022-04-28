// EngineRequestHandler.cs
// Author: Ondřej Ondryáš

using System.Reflection;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Protocol.Events;
using Code4Arm.ExecutionService.Hubs;
using Code4Arm.ExecutionService.Services;
using MediatR;
using Microsoft.AspNetCore.SignalR;
using Newtonsoft.Json;

namespace Code4Arm.ExecutionService.RequestHandlers;

public class EngineEventRequestHandler<TEvent> : IRequestHandler<EngineEvent<TEvent>> where TEvent : IProtocolEvent
{
    private readonly SessionManager _sessionManager;
    private readonly IHubContext<DebuggerSessionHub, IDebuggerSession> _hubContext;
    private readonly ILogger<EngineEventRequestHandler<TEvent>> _logger;
    private readonly string _eventName;

    public EngineEventRequestHandler(SessionManager sessionManager,
        IHubContext<DebuggerSessionHub, IDebuggerSession> hubContext,
        ILogger<EngineEventRequestHandler<TEvent>> logger)
    {
        _sessionManager = sessionManager;
        _hubContext = hubContext;
        _logger = logger;

        var eventName = typeof(TEvent).GetCustomAttribute<EventNameAttribute>()?.EventName;
        _eventName = eventName ?? throw new ArgumentException(
            $"Cannot create an engine event request handler for unannotated type {typeof(TEvent).FullName}.");
    }

    public async Task<Unit> Handle(EngineEvent<TEvent> request, CancellationToken cancellationToken)
    {
        var connectionId = _sessionManager.GetConnectionId(request.Engine);
        if (connectionId == null)
        {
            _logger.LogError("Cannot find connection for an existing engine!");

            return Unit.Value;
        }

        var client = _hubContext.Clients.Client(connectionId);
        
        await client.HandleEvent(_eventName, request.Event);
        return Unit.Value;
    }
}
