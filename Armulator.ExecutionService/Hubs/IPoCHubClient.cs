// IPoCHubClient.cs
// Author: Ondřej Ondryáš

namespace Armulator.ExecutionService.Hubs;

public interface IPoCHubClient
{
    Task ReceiveRegisters(PoCRegisterStatus registerStatus);
}
