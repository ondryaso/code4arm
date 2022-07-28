// ConnectionClearingBackgroundService.cs
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

using Code4Arm.ExecutionService.Services.Abstractions;

namespace Code4Arm.ExecutionService.Services;

public class ConnectionClearingBackgroundService : IHostedService, IDisposable
{
    private readonly ISessionManager _sessionManager;
    private readonly ILogger<ConnectionClearingBackgroundService> _logger;
    private Timer? _timer = null;

    public ConnectionClearingBackgroundService(ISessionManager sessionManager,
        ILogger<ConnectionClearingBackgroundService> logger)
    {
        _sessionManager = sessionManager;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Starting the connection clearing service.");

        _timer = new Timer(_ => _sessionManager.CleanConnections(),
            null, TimeSpan.Zero, TimeSpan.FromSeconds(10));

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Stopping the connection clearing service.");

        _timer?.Change(Timeout.Infinite, 0);

        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _timer?.Dispose();
    }
}
