// DebuggerException.cs
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

public class DebuggerException : Exception
{
    public int ErrorId { get; }
    public string ErrorMessage { get; }
    public DebuggerExceptionType ErrorType { get; }

    public DebuggerException(int id, string message, DebuggerExceptionType type,
        string description, Exception? innerException = null)
        : base(description, innerException)
    {
        ErrorId = id;
        ErrorMessage = message;
        ErrorType = type;
    }
}
