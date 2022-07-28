// ServiceOptions.cs
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

using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Execution.Configuration;

namespace Code4Arm.ExecutionService.Configuration;

public class ServiceOptions
{
    public AssemblerOptions AssemblerOptions { get; set; } = new();
    public LinkerOptions LinkerOptions { get; set; } = new();
    public ExecutionOptions DefaultExecutionOptions { get; set; } = new();
    public DebuggerOptions DefaultDebuggerOptions { get; set; } = new();

    public bool AllowInfiniteExecutionTimeout { get; set; } = false;
    public int ExecutionTimeoutLimit { get; set; } = 60000;
    public uint StackSizeLimit { get; set; } = 2 * 1024 * 1024;
    public string? AllowedLinkerOptionsRegex { get; set; }
    public string? AllowedAssemblerOptionsRegex { get; set; }

    public string RemoteFilesStorageDirectory { get; set; } = "RemoteFileStorage";
}
