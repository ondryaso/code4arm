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

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public static class ExceptionCodes
{
    public const int UnexpectedErrorId = 1000;
    public const string UnexpectedError = "unexpectedError";

    public const string InvalidExpression = "invalidExpression";
    public const int InvalidExpressionId = 100;

    public const string InvalidVariable = "invalidVariable";
    public const int InvalidVariableId = 101;

    public const string ExecutableNotLoaded = "executableNotLoaded";
    public const int ExecutableNotLoadedId = 102;

    public const int InvalidSourceId = 103;
    public const string InvalidSource = "invalidSource";

    public const int NotInitializedId = 104;
    public const string NotInitialized = "notInitialized";

    public const int ConfigurationId = 105;
    public const string Configuration = "configuration";

    public const int InvalidVariableFormatId = 106;
    public const string InvalidVariableFormat = "invalidFormat";

    public const int NoExceptionDataId = 107;
    public const string NoExceptionData = "noExceptionData";

    public const int StepBackNotEnabledId = 108;
    public const string StepBackNotEnabled = "stepbackNotEnabled";

    public const int InvalidGotoTargetId = 109;
    public const string InvalidGotoTarget = "invalidTarget";
    
    public const int InvalidMemoryReferenceId = 110;
    public const string InvalidMemoryReference = "invalidMemoryReference";
    
    public const int InvalidMemoryOperationId = 111;
    public const string InvalidMemoryOperation = "invalidMemoryOperation";

    public const int InvalidExecutionStateId = 112;
    public const string InvalidExecutionState = "invalidState";
    
    public const string VariableNotSettable = "variableNotSettable";
    public const int VariableNotSettableId = 113;
}
