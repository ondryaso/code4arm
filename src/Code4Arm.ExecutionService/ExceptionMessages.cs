// ExceptionMessages.cs
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

namespace Code4Arm.ExecutionService;

public class ExceptionMessages
{
    public const string NoLaunchTarget =
        "No build target specified. Either 'sourceDirectory' or 'sourceFiles' must be present in launch.json";

    public const string Assembling =
        "Cannot assemble {0} source(s). Check output for error details.";

    public const string Linking = "Cannot link assembled objects. Check output for more details.";

    public const string LaunchConfig
        = "Invalid launch configuration.";

    public const string LaunchConfigTimeoutTooSmall
        = $"{LaunchConfig} The minimal allowed execution timeout is {{0}} ms.";

    public const string LaunchConfigTimeoutTooBig
        = $"{LaunchConfig} The maximal allowed execution timeout is {{0}} ms.";

    public const string LaunchConfigInfiniteTimeout
        = $"{LaunchConfig} Infinite timeout is not allowed.";

    public const string LaunchConfigStackSizeTooBig
        = $"{LaunchConfig} The maximal allowed stack size is {{0}} B ({{1}} KiB).";

    public const string LaunchConfigInvalidEncoding
        = $"{LaunchConfig} Invalid C-string encoding specifier.";

    public const string LaunchConfigInvalidAssemblerOption
        = $"{LaunchConfig} Invalid assembler option {{0}}.";

    public const string LaunchConfigInvalidLinkerOption
        = $"{LaunchConfig} Invalid linker option {{0}}.";
}
