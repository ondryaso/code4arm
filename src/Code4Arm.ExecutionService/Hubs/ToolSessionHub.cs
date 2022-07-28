// ToolSessionHub.cs
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

#if REMOTE // Tool sessions are not used in the local mode

using Code4Arm.ExecutionService.ClientConfiguration;
using Code4Arm.ExecutionService.Files;
using Code4Arm.ExecutionService.Services;
using Code4Arm.ExecutionService.Services.Abstractions;
using Microsoft.AspNetCore.SignalR;

namespace Code4Arm.ExecutionService.Hubs;

public class ToolSessionHub : Hub
{
    private readonly ISessionManager<RemoteSession> _sessionManager;

    public ToolSessionHub(ISessionManager<RemoteSession> sessionManager)
    {
        _sessionManager = sessionManager;
    }

    public async Task<string> CreateSession()
    {
        var currentSession = await _sessionManager.GetSessionId(Context.ConnectionId);
        if (currentSession != null)
            await _sessionManager.RemoveConnection(Context.ConnectionId);

        var session = await _sessionManager.CreateSession(Context.ConnectionId);

        return session;
    }

    public async Task<bool> AttachToSession(string sessionId)
    {
        var currentSession = await _sessionManager.GetSessionId(Context.ConnectionId);
        if (currentSession != null)
            await _sessionManager.RemoveConnection(Context.ConnectionId);

        try
        {
            await _sessionManager.AssignConnection(Context.ConnectionId, sessionId, ConnectionType.Tool);
        }
        catch (ArgumentException)
        {
            return false;
        }

        return true;
    }

    private async ValueTask<RemoteSession> GetSession()
    {
        var sessionId = await _sessionManager.GetSessionId(Context.ConnectionId);

        if (sessionId == null)
            throw new HubException("No session attached.");

        var session = await _sessionManager.GetSession(sessionId);

        if (session == null)
            throw new HubException("No session attached.");

        return session;
    }

    public async Task<IEnumerable<int>> RequestedFiles(RemoteFileMetadata[] files)
    {
        var session = await this.GetSession();

        var trackedFiles = new Dictionary<string, int>(await session.GetTrackedFiles());
        var ret = new List<int>();

        for (var i = 0; i < files.Length; i++)
        {
            var fileVersion = files[i];

            if (!trackedFiles.TryGetValue(fileVersion.Name, out var localVersion)
                || localVersion != fileVersion.Version)
                ret.Add(i);
        }

        session.SetFiles(files);

        return ret;
    }

    public async Task SyncFiles(RemoteFileMetadata[] files)
    {
        var session = await this.GetSession();

        foreach (var fileVersion in files)
        {
            if (fileVersion.Text == null)
                continue;

            await session.UpdateFile(fileVersion.Name, fileVersion.Version, fileVersion.Text);
        }
    }

    public async Task CloseSession()
    {
        await _sessionManager.RemoveConnection(Context.ConnectionId);
    }

    public async Task UseClientConfiguration(ClientToolConfiguration configuration)
    {
        var session = await this.GetSession();
        session.SessionOptions = configuration;
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        await base.OnDisconnectedAsync(exception);
        await this.CloseSession();
    }
}
#endif
