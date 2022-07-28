// AssemblerOptions.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

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
