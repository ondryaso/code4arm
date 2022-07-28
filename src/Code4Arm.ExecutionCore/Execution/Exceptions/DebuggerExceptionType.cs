// DebuggerExceptionType.cs
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

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public enum DebuggerExceptionType
{
    /// <summary>
    /// The error is presented to the user explicitly (e.g. in a pop-up dialog).
    /// In terms of the protocol, this is an ErrorResponse with showUser set to true.
    /// </summary>
    User,
    /// <summary>
    /// The error is logged in the debugger console.
    /// In terms of the protocol, this error triggers an OutputEvent with the 'console' category.
    /// </summary>
    Log,
    /// <summary>
    /// The error is presented as an invalid result of an operation (e.g. evaluating an expression).
    /// In terms of the protocol, this is an ErrorResponse with showUser set to false.
    /// </summary>
    UserImplicit,
    /// <summary>
    /// The error has been caused by using a protocol method in an inappropriate state (e.g. calling a debugger
    /// method when the engine is not running) or with invalid arguments (e.g. a wrong variables reference).
    /// </summary>
    InvalidRequest
}
