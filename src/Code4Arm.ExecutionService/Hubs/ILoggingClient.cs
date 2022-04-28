// ILoggingClient.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionService.Hubs;

public interface ILoggingClient
{
    Task Log(LogLevel level, int eventId, string? eventName, string message);
}
