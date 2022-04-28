// LaunchRequest.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Protocol.Requests;

namespace Code4Arm.ExecutionService.HubRequests;

public record CustomLaunchArguments(string? SourceDirectory, string[]? SourceFiles) : LaunchRequestArguments;
