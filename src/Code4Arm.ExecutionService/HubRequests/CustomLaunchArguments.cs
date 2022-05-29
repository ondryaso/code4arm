// LaunchRequest.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.ExecutionService.ClientConfiguration;
using Code4Arm.ExecutionService.Services.Abstractions;

namespace Code4Arm.ExecutionService.HubRequests;

public record CustomLaunchArguments(string? SourceDirectory, string[]? SourceFiles) : LaunchRequestArguments,
    ISessionLaunchArguments
{
    public DebuggerOptionsOverlay? DebuggerOptions { get; init; }
}
