// ClientLogger.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionService.Hubs;
using Microsoft.AspNetCore.SignalR;

namespace Code4Arm.ExecutionService.Services;

public class RemoteLogger : ILogger
{
    private readonly string _category;
    private readonly RemoteLoggerFactory _factory;
    private readonly IHubContext<DebuggerSessionHub, IDebuggerSession> _hubContext;

    internal RemoteLogger(string category, RemoteLoggerFactory factory,
        IHubContext<DebuggerSessionHub, IDebuggerSession> hubContext)
    {
        _category = category;
        _factory = factory;
        _hubContext = hubContext;
    }

    public IDisposable BeginScope<TState>(TState state) => throw new NotSupportedException();

    public bool IsEnabled(LogLevel logLevel) => (int)_factory.LogLevel <= (int)logLevel;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        if (!this.IsEnabled(logLevel))
            return;

        var client = _hubContext.Clients.Client(_factory.ConnectionId);
        Task.Run(async () => await client.Log(_category, DateTime.UtcNow, logLevel, eventId.Id, eventId.Name,
            formatter(state, exception)));
    }
}

public class RemoteLoggerFactory : ILoggerFactory
{
    internal readonly string ConnectionId;
    private readonly IServiceProvider _serviceProvider;

    public RemoteLoggerFactory(string connectionId, IServiceProvider serviceProvider)
    {
        ConnectionId = connectionId;
        _serviceProvider = serviceProvider;
    }

    public LogLevel LogLevel { get; set; }

    public void Dispose()
    {
    }

    public void AddProvider(ILoggerProvider provider)
    {
        throw new NotSupportedException();
    }

    public ILogger CreateLogger(string categoryName)
    {
        var hubContext = _serviceProvider.GetRequiredService<IHubContext<DebuggerSessionHub, IDebuggerSession>>();
        var logger = new RemoteLogger(categoryName, this, hubContext);

        return logger;
    }
}
