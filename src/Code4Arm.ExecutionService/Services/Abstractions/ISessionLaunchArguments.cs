// ISessionLaunchArguments.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionService.Services.Abstractions;

public interface ISessionLaunchArguments : IClientConfiguration
{
    string? SourceDirectory { get; }
    string[]? SourceFiles { get; }
}
