// ILoggingClient.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionService.Hubs;

public interface ILoggingClient
{
    Task Log(int code, string message, string description);
}
