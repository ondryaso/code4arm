// DebuggerOptionsOverlay.cs
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

using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Debugger;

namespace Code4Arm.ExecutionService.ClientConfiguration;

/// <summary>
/// A configuration overlay for <see cref="DebuggerOptions"/>.
/// For property reference, see its documentation.
/// </summary>
public class DebuggerOptionsOverlay
{
    public bool? EnableAutomaticDataVariables { get; set; }
    public bool? EnableStackVariables { get; set; }
    public bool? EnableRegistersVariables { get; set; }
    public bool? EnableSimdVariables { get; set; }
    public bool? EnableControlVariables { get; set; }
    public bool? EnableExtendedControlVariables { get; set; }
    public bool? PadUnsignedBinaryNumbers { get; set; }
    public VariableNumberFormat? VariableNumberFormat { get; set; }
    public DebuggerVariableType[]? RegistersSubtypes { get; set; }
    public DebuggerVariableType[]? StackVariablesSubtypes { get; set; }
    public bool? ShowFloatIeeeSubvariables { get; set; }
    public SimdRegisterLevel? TopSimdRegistersLevel { get; set; }
    public ArmSimdRegisterVariableOptionsOverlay? SimdRegistersOptions { get; set; }
    public int? CStringMaxLength { get; set; }
    public string? CStringEncoding { get; set; }
    public bool? ShowRunningAtMessage { get; set; }
}
