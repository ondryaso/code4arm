// LogRequest.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionService.Hubs;
using MediatR;
using Microsoft.AspNetCore.SignalR;

namespace Code4Arm.ExecutionService.HubRequests;

public record LogRequest<THub, TClient>(string ConnectionId, LogLevel Level, string Message, int EventId = 0,
    string? EventName = null) : IRequest
    where TClient : class, ILoggingClient where THub : Hub<TClient>;
