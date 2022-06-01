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
    public ExecutionOptionsOverlay? ExecutionOptions { get; init; }

    public string[]? AssemblerOptions { get; init; }
    public string[]? LdOptions { get; init; }
    public string[]? LdTrailOptions { get; init; }
    public uint? TrampolineStartAddress { get; init; }
    public uint? TrampolineEndAddress { get; init; }
}
