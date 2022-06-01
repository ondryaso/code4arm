// LinkerOptions.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Assembling.Configuration;

public record LinkerOptions
{
    public string LdPath { get; init; } = string.Empty;
    public string[]? LdOptions { get; init; }
    public string[]? LdTrailOptions { get; init; }
    public string? LinkerScript { get; init; } = Utils.GetSupportFile("linker_script.x");
    public string? InitFilePath { get; init; } = Utils.GetSupportFile("init.s");
    public int TimeoutMs { get; init; } = 5000;
    public uint TrampolineStartAddress { get; init; } = 0xff000000;
    public uint TrampolineEndAddress { get; init; } = 0xfffffffc;
}
