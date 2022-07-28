// ExceptionCodes.cs
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

public static class ExceptionCodes
{
    public const int UnexpectedErrorId = ExecutionCore.Execution.Exceptions.ExceptionCodes.UnexpectedErrorId;
    public const string UnexpectedError = ExecutionCore.Execution.Exceptions.ExceptionCodes.UnexpectedError;
    
    public const int NoLaunchTargetId = 200;
    public const string NoLaunchTarget = "noTarget";
    
    public const int AssembleId = 201;
    public const string Assemble = "assemble";
    
    public const int LinkId = 202;
    public const string Link = "link";

    public const int LaunchConfigId = 203;
    public const string LaunchConfig = "launchConfiguration";
}
