// EngineEventRequestHandler.cs
// Author: Ondřej Ondryáš

using System.Reflection;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Protocol.Events;
using Code4Arm.ExecutionService.Hubs;
using Code4Arm.ExecutionService.Services.Abstractions;
using MediatR;
using Microsoft.AspNetCore.SignalR;

namespace Code4Arm.ExecutionService.RequestHandlers;

public class EngineEventRequestHandler<TEvent, THub> : IRequestHandler<EngineEvent<TEvent>>
    where TEvent : IProtocolEvent
    where THub : Hub<IDebuggerSession>
{
    private readonly ISessionManager _sessionManager;
    private readonly IHubContext<THub, IDebuggerSession> _hubContext;
    private readonly ILogger<EngineEventRequestHandler<TEvent, THub>> _logger;
    private readonly string _eventName;
    private readonly bool _isEmpty;

    public EngineEventRequestHandler(ISessionManager sessionManager,
        IHubContext<THub, IDebuggerSession> hubContext,
        ILogger<EngineEventRequestHandler<TEvent, THub>> logger)
    {
        _sessionManager = sessionManager;
        _hubContext = hubContext;
        _logger = logger;

        var eventAttribute = typeof(TEvent).GetCustomAttribute<ProtocolEventAttribute>();

        if (eventAttribute == null)
            throw new ArgumentException(
                $"Cannot create an engine event request handler for unannotated type {typeof(TEvent).FullName}.");

        _eventName = eventAttribute.EventName;
        _isEmpty = eventAttribute.IsEmpty;
    }

    public async Task<Unit> Handle(EngineEvent<TEvent> request, CancellationToken cancellationToken)
    {
        var sessionId = await _sessionManager.GetSessionId(request.Engine);
        if (sessionId == null)
        {
            _logger.LogError("Cannot find session for an existing engine!");

            return Unit.Value;
        }

        var connectionId = await _sessionManager.GetConnectionId(sessionId, ConnectionType.Debugger);
        if (connectionId == null)
        {
            _logger.LogError("Cannot find debugger connection for an existing engine!");

            await _sessionManager.Log(sessionId, ExceptionCodes.UnexpectedErrorId, ExceptionCodes.UnexpectedError,
                $"Attempted to dispatch event {_eventName} but no debugger is connected.", ConnectionType.Tool);

            return Unit.Value;
        }

        var client = _hubContext.Clients.Client(connectionId);

        await client.HandleEvent(_eventName, _isEmpty ? null : request.Event);

        return Unit.Value;
    }
}
