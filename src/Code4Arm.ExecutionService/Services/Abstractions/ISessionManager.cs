// ISessionManager.cs
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
