// GenericSessionManager.cs
// Author: Ondřej Ondryáš

using System.Collections.Concurrent;
using System.Reflection;
using Code4Arm.ExecutionCore.Execution;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionService.Extensions;
using Code4Arm.ExecutionService.Hubs;
using Code4Arm.ExecutionService.Services.Abstractions;
using Microsoft.AspNetCore.SignalR;
using ISession = Code4Arm.ExecutionService.Services.Abstractions.ISession;

// ReSharper disable InconsistentlySynchronizedField

namespace Code4Arm.ExecutionService.Services;

public abstract class GenericSessionManager<TSession, TToolHub, TDebuggerHub, TToolHubClient,
    TDebuggerHubClient> : ISessionManager<TSession>
    where TSession : class, ISession
    where TToolHub : Hub<TToolHubClient>
    where TDebuggerHub : Hub<TDebuggerHubClient>
    where TToolHubClient : class, ILoggingClient
    where TDebuggerHubClient : class, ILoggingClient
{
    protected readonly IHubContext<TToolHub, TToolHubClient> ToolHub;
    protected readonly IHubContext<TDebuggerHub, TDebuggerHubClient> DebuggerHub;
    protected readonly ILogger Logger;

    private class SessionWrapper
    {
        public readonly TSession Session;
        public string? DebuggerConnectionId { get; set; }
        public string? ToolConnectionId { get; set; }

        public readonly object SessionLocker = new object();
        public bool Removed { get; set; }

        public SessionWrapper(TSession session)
        {
            Session = session;
        }
    }

    private readonly ConcurrentDictionary<Guid, SessionWrapper> _sessions = new();
    private readonly ConcurrentDictionary<string, SessionWrapper> _connections = new();
    private readonly ConcurrentDictionary<IExecutionEngine, SessionWrapper> _engines = new();

    private readonly ConcurrentDictionary<string, ManualResetEventSlim> _waitingDebuggers = new();

    public GenericSessionManager(IHubContext<TToolHub, TToolHubClient> toolHub,
        IHubContext<TDebuggerHub, TDebuggerHubClient> debuggerHub, ILoggerFactory loggerFactory)
    {
        ToolHub = toolHub;
        DebuggerHub = debuggerHub;
        Logger = loggerFactory.CreateLogger(this.GetType());
    }

    public async Task<string> CreateSession(string? toolConnectionId = null)
    {
        var guid = Guid.NewGuid();
        var session = await this.MakeSession(guid);
        var success = false;

        while (!success)
        {
            success = _sessions.TryAdd(guid, new SessionWrapper(session)
                { ToolConnectionId = toolConnectionId });

            if (success)
            {
                if (toolConnectionId != null)
                    await this.AssignConnection(toolConnectionId, session.SessionId, ConnectionType.Tool);

                break;
            }

            session.Dispose();
            guid = Guid.NewGuid();
            session = await this.MakeSession(guid);
        }

        session.EngineCreated += this.EngineCreatedHandler;

        return guid.ToString();
    }

    protected abstract ValueTask<TSession> MakeSession(Guid sessionId);

    private void EngineCreatedHandler(object? sender, EngineCreatedEventArgs e)
    {
        if (sender is not ISession session)
            return;

        if (!Guid.TryParse(session.SessionId, out var guid))
            return;

        if (!_sessions.TryGetValue(guid, out var wrapper))
            return;

        if (e.OldEngine != null)
            _engines.TryRemove(e.OldEngine, out _);

        _engines.TryAdd(e.NewEngine, wrapper);

        if (!Logger.IsEnabled(LogLevel.Debug))
            return;

        if (e.NewEngine is ExecutionEngine ee)
        {
            var eeId = ee.GetType().GetField("_executionId",
                BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(ee);

            Logger.LogDebug("Changed engine on session {SessionId}. New execution ID: {ExecutionId}",
                wrapper.Session.SessionId, eeId);
        }
        else
        {
            Logger.LogDebug("Changed engine on session {SessionId}.", wrapper.Session.SessionId);
        }
    }

    public Task CloseSession(string sessionId)
    {
        if (!Guid.TryParse(sessionId, out var guid))
            return Task.CompletedTask;

        if (_sessions.TryRemove(guid, out var session))
        {
            Logger.LogDebug("Removing session {SessionId} (explicitly).", sessionId);

            lock (session.SessionLocker)
            {
                session.Session.Dispose();

                if (session.DebuggerConnectionId != null)
                    _connections.TryRemove(session.DebuggerConnectionId, out _);
                if (session.ToolConnectionId != null)
                    _connections.TryRemove(session.ToolConnectionId, out _);

                session.Removed = true;
            }
        }

        return Task.CompletedTask;
    }

    public Task AssignConnection(string connectionId, string sessionId, ConnectionType type)
    {
        if (!Guid.TryParse(sessionId, out var guid))
            throw new ArgumentException("Invalid session ID.", nameof(sessionId));

        if (!_sessions.TryGetValue(guid, out var wrapper))
            throw new ArgumentException("Invalid session ID.", nameof(sessionId));

        Logger.LogDebug("Adding connection {ConnectionId} to session {SessionId}.",
            connectionId, sessionId);

        lock (wrapper.SessionLocker)
        {
            if (wrapper.Removed)
                throw new ArgumentException("Invalid session ID.", nameof(sessionId));

            if (type == ConnectionType.Debugger)
            {
                wrapper.DebuggerConnectionId = connectionId;

                var re = _waitingDebuggers.GetOrAdd(connectionId, _ => new ManualResetEventSlim(true));
                re.Set();
            }
            else
            {
                wrapper.ToolConnectionId = connectionId;
            }

            if (!_connections.TryAdd(connectionId, wrapper))
            {
                if (wrapper.DebuggerConnectionId == connectionId && type == ConnectionType.Tool)
                    wrapper.ToolConnectionId = connectionId;
                else if (wrapper.ToolConnectionId == connectionId && type == ConnectionType.Debugger)
                    wrapper.DebuggerConnectionId = connectionId;
                else
                    throw new InvalidOperationException("Connection already assigned to a session.");
            }
        }

        return Task.CompletedTask;
    }

    public Task RemoveConnection(string connectionId)
    {
        if (!_connections.TryRemove(connectionId, out var session))
            return Task.CompletedTask;

        Logger.LogDebug("Removing connection {ConnectionId} from session {SessionId}.",
            connectionId, session.Session.SessionId);

        lock (session.SessionLocker)
        {
            if (session.DebuggerConnectionId == connectionId)
            {
                session.DebuggerConnectionId = null;
                if (_waitingDebuggers.TryRemove(connectionId, out var re))
                    re.Dispose();
            }

            if (session.ToolConnectionId == connectionId)
                session.ToolConnectionId = null;
        }

        return Task.CompletedTask;
    }

    public async Task WaitForDebuggerAttachment(string connectionId)
    {
        if (_connections.TryGetValue(connectionId, out var session) && session.DebuggerConnectionId == connectionId)
        {
            if (_waitingDebuggers.TryGetValue(connectionId, out var existingRe))
                existingRe.Dispose();

            return;
        }

        var re = _waitingDebuggers.GetOrAdd(connectionId, _ => new ManualResetEventSlim(false));
        await re.WaitHandle.AsTask();
        _waitingDebuggers.TryRemove(connectionId, out _);
        re.Dispose();
    }

    public ValueTask<string?> GetSessionId(string connectionId)
    {
        return _connections.TryGetValue(connectionId, out var session)
            ? new ValueTask<string?>(session.Session.SessionId)
            : ValueTask.FromResult((string?)null);
    }

    public ValueTask<string?> GetSessionId(IExecutionEngine engine)
    {
        return _engines.TryGetValue(engine, out var session)
            ? new ValueTask<string?>(session.Session.SessionId)
            : ValueTask.FromResult((string?)null);
    }

    public ValueTask<string?> GetConnectionId(string sessionId, ConnectionType type)
    {
        if (!Guid.TryParse(sessionId, out var guid))
            return ValueTask.FromResult<string?>(null);

        return _sessions.TryGetValue(guid, out var session)
            ? new ValueTask<string?>(session.DebuggerConnectionId)
            : ValueTask.FromResult((string?)null);
    }

    public async Task Log(string sessionId, int code, string message, string description, ConnectionType? targetHint)
    {
        if (!Guid.TryParse(sessionId, out var guid))
            return;

        if (!_sessions.TryGetValue(guid, out var session))
            return;

        var debuggerConnId = session.DebuggerConnectionId;
        var toolConnId = session.ToolConnectionId;

        if (targetHint is null or ConnectionType.Debugger && debuggerConnId != null)
            await DebuggerHub.Clients.Client(debuggerConnId).Log(code, message, description);

        if (targetHint is null or ConnectionType.Tool && toolConnId != null)
            await ToolHub.Clients.Client(toolConnId).Log(code, message, description);
    }

    public ValueTask<TSession?> GetSession(string sessionId)
    {
        if (!Guid.TryParse(sessionId, out var guid))
            return ValueTask.FromResult<TSession?>(null);

        return _sessions.TryGetValue(guid, out var session)
            ? new ValueTask<TSession?>(session.Session)
            : ValueTask.FromResult((TSession?)null);
    }

    public void CleanConnections()
    {
        if (!_sessions.IsEmpty)
        {
            var snapshot = _sessions.ToArray();

            foreach (var (id, wrapper) in snapshot)
            {
                lock (wrapper.SessionLocker)
                {
                    if (wrapper is { DebuggerConnectionId: null, ToolConnectionId: null })
                    {
                        Logger.LogDebug("Removing session {SessionId} (no connections).", id);

                        if (_sessions.TryRemove(id, out _))
                            wrapper.Session.Dispose();
                    }
                }
            }
        }

        if (_waitingDebuggers.IsEmpty)
            return;

        var waitingDebuggersSnapshot = _waitingDebuggers.ToArray();
        foreach (var (connectionId, re) in waitingDebuggersSnapshot)
        {
            if (re.IsSet)
            {
                if (_waitingDebuggers.TryRemove(connectionId, out _))
                {
                    re.Dispose();
                    Logger.LogDebug("Disposed waiting event for debugger connection {ConnectionId} (cleaning up).", connectionId);
                }
            }
        }
    }
}
