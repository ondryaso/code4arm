// ExecutionState.cs
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

using Code4Arm.ExecutionCore.Assembling.Models;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

/// <summary>
/// Determines the possible states of an <see cref="IExecutionEngine"/>.
/// </summary>
public enum ExecutionState
{
    /// <summary>
    /// No <see cref="Executable"/> has been loaded, execution cannot be launched.
    /// </summary>
    Unloaded,

    /// <summary>
    /// An <see cref="Executable"/> has been loaded and it is waiting to be launched.
    /// </summary>
    Ready,

    /// <summary>
    /// The execution (emulation) is running.
    /// </summary>
    Running,

    /// <summary>
    /// The execution has been paused after a step, 'Goto' jump or explicit user-initiated pause.
    /// </summary>
    Paused,

    /// <summary>
    /// The execution has been paused after hitting a breakpoint.
    /// </summary>
    PausedBreakpoint,

    /// <summary>
    /// The execution has been paused after a runtime (in emulated CPU) exception occured.
    /// </summary>
    PausedException,

    /// <summary>
    /// The execution (emulation) has reached the end of the program and finished.
    /// </summary>
    Finished
}
