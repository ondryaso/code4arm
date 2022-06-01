// IClientConfiguration.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionService.ClientConfiguration;

namespace Code4Arm.ExecutionService.Services.Abstractions;

public interface IClientConfiguration
{
    DebuggerOptionsOverlay? DebuggerOptions { get; }
    ExecutionOptionsOverlay? ExecutionOptions { get; }

    string[]? AssemblerOptions { get; }
    string[]? LdOptions { get; }
    string[]? LdTrailOptions { get; }
    uint? TrampolineStartAddress { get; }
    uint? TrampolineEndAddress { get; }
}
