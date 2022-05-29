// ISessionManager.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionService.ClientConfiguration;

namespace Code4Arm.ExecutionService.Services.Abstractions;

public class EngineCreatedEventArgs : EventArgs
{
    public IExecutionEngine NewEngine { get; }
    public IExecutionEngine? OldEngine { get; }

    public EngineCreatedEventArgs(IExecutionEngine newEngine, IExecutionEngine? oldEngine)
    {
        NewEngine = newEngine;
        OldEngine = oldEngine;
    }
}

public interface ISession : IDisposable
{
    string SessionId { get; }
    ValueTask<IExecutionEngine> GetEngine();
    Task BuildAndLoad(ISessionLaunchArguments launchArguments);

    event EventHandler<EngineCreatedEventArgs> EngineCreated;
    
    DebuggerOptionsOverlay? SessionDebuggerOptions { get; set; }
    ExecutionOptionsOverlay? SessionExecutionOptions { get; set; }
}

public enum ConnectionType
{
    Tool,
    Debugger
}

public interface ISessionManager
{
    Task<string> CreateSession();
    Task CloseSession(string sessionId);

    Task AssignConnection(string connectionId, string sessionId, ConnectionType connectionType);
    Task RemoveConnection(string connectionId);
    ValueTask<string?> GetSessionId(string connectionId);
    ValueTask<string?> GetSessionId(IExecutionEngine engine);
    ValueTask<string?> GetConnectionId(string sessionId, ConnectionType connectionType);

    Task Log(string sessionId, int code, string message, string description, ConnectionType? targetHint);

    void CleanConnections();
}

public interface ISessionManager<TSession> : ISessionManager where TSession : ISession
{
    ValueTask<TSession?> GetSession(string sessionId);
}
