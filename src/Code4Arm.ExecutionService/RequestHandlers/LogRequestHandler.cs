// LogRequestHandler.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionService.HubRequests;
using Code4Arm.ExecutionService.Hubs;
using MediatR;
using Microsoft.AspNetCore.SignalR;

namespace Code4Arm.ExecutionService.RequestHandlers;

public class LogRequestHandler<THub, TClient> : IRequestHandler<LogRequest<THub, TClient>, Unit>
    where TClient : class, ILoggingClient where THub : Hub<TClient>
{
    private readonly IHubContext<THub, TClient> _hubContext;
    private readonly ILogger<LogRequestHandler<THub, TClient>> _logger;

    public LogRequestHandler(IHubContext<THub, TClient> hubContext, ILogger<LogRequestHandler<THub, TClient>> logger)
    {
        _hubContext = hubContext;
        _logger = logger;
    }

    public async Task<Unit> Handle(LogRequest<THub, TClient> request, CancellationToken cancellationToken)
    {
        var client = _hubContext.Clients.Client(request.ConnectionId);
        await client
              .Log(request.Category, request.TimestampUtc, request.Level, request.EventId, request.EventName,
                  request.Message).ConfigureAwait(false);

        return Unit.Value;
    }
}
