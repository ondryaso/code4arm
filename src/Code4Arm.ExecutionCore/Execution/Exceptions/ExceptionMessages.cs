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

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public static class ExceptionMessages
{
    public const string InvalidExpression = "Invalid expression.";
    public const string InvalidExpressionTop = "Invalid expression: the general syntax is (type)expression:format.";
    public const string InvalidExpressionTypeSpecifier = "Invalid value type specifier.";
    public const string InvalidExpressionFormatSpecifier = "Invalid value format specifier.";
    public const string InvalidExpressionAddressing = "Invalid addressing expression: the general syntax is (type) [ Rx/address/symbol, Roffset/offset_value, shift shift_value ] :format";
    public const string InvalidExpressionTypeSpecifierUnavailable = "The value type specifier cannot be used for this register.";
    public const string InvalidExpressionIndexer = "Invalid subtype index.";
    public const string InvalidExpressionNotSettable = "Value cannot be set for this expression.";
    public const string InvalidExpressionRegister = "Invalid register name.";
    
    public const string InvalidVariable = "Invalid variable reference.";
    public const string ExecutableNotLoaded = "No executable loaded.";
    public const string InvalidExecutionState = "Cannot perform this action while execution is in state {0}.";
    public const string InvalidExecutionLaunchState = "Execution has already been launched.";
    public const string InvalidSource = "Invalid source reference.";
    public const string NotInitialized = "The debugger is not initialized. Issue an Initialize request first.";
    public const string InvalidVariableFormat = "Invalid input format.";
    public const string VariableNotSettable = "This variable cannot be set.";
    
    public const string InvalidVariableFormat32 = "Invalid format. Expected a 32bit integer or float. For hexa input, use '0x' prefix or 'x' suffix. For binary input, use '0b' prefix or 'b' suffix.";
    public const string InvalidVariableFormat32Float = "Invalid format. Expected a 32bit single-precision floating-point number.";
    public const string InvalidVariableFormat32Binary = "Invalid format. Expected a 32bit binary number.";
    public const string InvalidVariableFormat64Float = "Invalid format. Expected a 64bit double-precision floating-point number.";
    public const string InvalidVariableFormat64Binary = "Invalid format. Expected a 64bit binary number.";

    public const string NoExceptionData = "No exception data found.";
    public const string StepBackNotEnabled = "Stepping back is not possible in the current context.";
    public const string InvalidGotoTarget = "Invalid jump target address.";
    public const string InvalidMemoryReference = "Invalid memory reference (address).";
    public const string InvalidMemoryRead = "Invalid memory read (memory not mapped).";
    public const string InvalidMemoryWrite = "Invalid memory write (memory not mapped).";
    public const string InvalidMemorySize = "Invalid memory operation – requested amount is too big or negative.";

    public const string GeneralError = "An unexpected critical error occured. Terminating execution.";
}
