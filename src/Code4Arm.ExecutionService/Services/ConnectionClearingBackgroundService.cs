// ConnectionClearingBackgroundService.cs
// Author: Ondřej Ondryáš

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
