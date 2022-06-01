// AssemblerOptions.cs
// Author: Ondřej Ondryáš

using Microsoft.Extensions.Options;

namespace Code4Arm.ExecutionCore.Assembling.Configuration;

public record AssemblerOptions
{
    public string GasPath { get; init; } = string.Empty;
    public string[]? GasOptions { get; init; }
    public string? SourceHeaderPath { get; init; } = Utils.GetSupportFile("source_header.s");
    public int TimeoutMs { get; init; } = 5000;
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
