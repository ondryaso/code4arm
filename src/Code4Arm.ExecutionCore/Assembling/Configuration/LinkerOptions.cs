// LinkerOptions.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Assembling.Configuration;

public class LinkerOptions
{
    public string LdPath { get; set; } = "ld"; // TODO
    public string[]? LdOptions { get; set; }
    public string[]? LdTrailOptions { get; set; }
    public string? LinkerScript { get; set; } = Path.Combine("SupportFiles", "linker_script.x");
    public string? InitFilePath { get; set; } = Path.Combine("SupportFiles", "init.s");
    public int TimeoutMs { get; set; } = 5000;
    public uint TrampolineStartAddress { get; set; } = 0xff000000;
    public uint TrampolineEndAddress { get; set; } = 0xfffffffc;
}
