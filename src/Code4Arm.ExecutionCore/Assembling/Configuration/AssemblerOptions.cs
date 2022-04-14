// AssemblerOptions.cs
// Author: Ondřej Ondryáš

using Microsoft.Extensions.Options;

namespace Code4Arm.ExecutionCore.Assembling.Configuration;

public class AssemblerOptions
{
    public string GasPath { get; set; } = "as"; // TODO
    public string[]? GasOptions { get; set; } = new[] {"-march=armv8.6-a+fp16"};
    public string? SourceHeaderPath { get; set; } = Path.Combine("SupportFiles", "source_header.s");
    public int TimeoutMs { get; } = 5000;
}

public class AssemblerOptionsValidator : IValidateOptions<AssemblerOptions>
{
    public ValidateOptionsResult Validate(string name, AssemblerOptions options)
    {
        if (options.GasOptions != null)
        {
            if (options.GasOptions.Any(a => a.Trim().StartsWith("-o")))
                return ValidateOptionsResult.Fail("GAS options cannot contain the '-o' output parameter.");
            if (options.GasOptions.Any(a => a.Trim().StartsWith("-a")))
                return ValidateOptionsResult.Fail("GAS options cannot contain the '-a' output parameter.");
        }

        return ValidateOptionsResult.Success;
    }
}