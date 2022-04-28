// IClient.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionService.Hubs;

public interface IDebuggerSession : ILoggingClient
{
    Task HandleEvent(string eventName, object body);
}
