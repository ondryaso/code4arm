// ArmSimdRegisterVariableOptions.cs
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

using Code4Arm.ExecutionCore.Execution.Debugger;

namespace Code4Arm.ExecutionCore.Execution.Configuration;

public record ArmSimdRegisterVariableOptions
{
    /// <summary>
    /// Different subtypes to break the D registers' values into. 
    /// </summary>
    /// <remarks>
    /// Currently, only <see cref="DebuggerVariableType.Float"/>, <see cref="DebuggerVariableType.IntU"/>,
    /// <see cref="DebuggerVariableType.LongU"/> and <see cref="DebuggerVariableType.Double"/>
    /// are supported.
    /// </remarks>
    public DebuggerVariableType[]? QSubtypes { get; init; }

    /// <summary>
    /// Show D registers.
    /// </summary>
    public bool ShowD { get; init; }
        
    /// <summary>
    /// Different subtypes to break the D registers' values into. 
    /// </summary>
    public DebuggerVariableType[]? DSubtypes { get; init; }
    
    /// <summary>
    /// Show IEEE 754 decomposition variables for the 64b values in the D registers.
    /// </summary>
    public bool DIeeeSubvariables { get; init; }

    /// <summary>
    /// Show S registers.
    /// </summary>
    public bool ShowS { get; init; }
    
    /// <summary>
    /// Different subtypes to break the S registers' values into. 
    /// </summary>
    /// <remarks>
    /// <see cref="DebuggerVariableType.LongS"/>, <see cref="DebuggerVariableType.LongU"/> and <see cref="DebuggerVariableType.Double"/> cannot be used here
    /// because the registers are 32 bits wide.
    /// </remarks>
    public DebuggerVariableType[]? SSubtypes { get; init; }
    
    /// <summary>
    /// Show IEEE 754 decomposition variables for the 32b values in the S registers.
    /// </summary>
    public bool SIeeeSubvariables { get; init; }

    /// <summary>
    /// If true, D and S registers will be interpreted and rendered as floating point numbers in their corresponding variables.
    /// </summary>
    public bool PreferFloatRendering { get; init; }
}
