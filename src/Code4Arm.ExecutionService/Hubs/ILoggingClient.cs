// ILoggingClient.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionService.Hubs;

public interface ILoggingClient
{
    Task Log(string category, DateTime timestampUtc, LogLevel level, int eventId, string? eventName, string message);
}
