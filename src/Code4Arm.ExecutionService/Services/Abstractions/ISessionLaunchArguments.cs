// ISessionLaunchArguments.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionService.ClientConfiguration;

namespace Code4Arm.ExecutionService.Services.Abstractions;

public interface ISessionLaunchArguments
{
    string? SourceDirectory { get; }
    string[]? SourceFiles { get; }

    DebuggerOptionsOverlay? DebuggerOptions { get; }
    ExecutionOptionsOverlay ExecutionOptions { get; }
}
