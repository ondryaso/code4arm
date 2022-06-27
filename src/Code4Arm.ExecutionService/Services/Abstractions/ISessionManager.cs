// ISessionManager.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;

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

    IClientConfiguration? SessionOptions { get; set; }

    ValueTask<IEnumerable<KeyValuePair<string, int>>> GetTrackedFiles();
}

public enum ConnectionType
{
    Tool,
    Debugger
}

public interface ISessionManager
{
    Task<string> CreateSession(string? toolConnectionId = null);
    Task CloseSession(string sessionId);

    Task AssignConnection(string connectionId, string sessionId, ConnectionType connectionType);
    Task RemoveConnection(string connectionId);
    Task WaitForDebuggerAttachment(string connectionId);
    
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
