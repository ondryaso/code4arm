// ClientToolConfiguration.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionService.Services.Abstractions;

namespace Code4Arm.ExecutionService.ClientConfiguration;

public class ClientToolConfiguration : IClientConfiguration
{
    public DebuggerOptionsOverlay? DebuggerOptions { get; set; }
    public ExecutionOptionsOverlay? ExecutionOptions { get; set; }
    public string[]? AssemblerOptions { get; set; }
    public string[]? LdOptions { get; set; }
    public string[]? LdTrailOptions { get; set; }
    public uint? TrampolineStartAddress { get; set; }
    public uint? TrampolineEndAddress { get; set; }
}
