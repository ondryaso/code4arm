// LinkerOptions.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Assembling.Configuration;

public class LinkerOptions
{
    public string LdPath { get; set; } = "ld"; // TODO
    public string[]? LdOptions { get; set; }
    public string[]? LdTrailOptions { get; set; }
    public int TimeoutMs { get; set; } = 5000;
    public uint TrampolineStartAddress { get; set; } = 0xffff0000;
}
