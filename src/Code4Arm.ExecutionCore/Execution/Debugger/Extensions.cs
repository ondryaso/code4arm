// Extensions.cs
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

using System.Reflection;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public static class Extensions
{
    /// <summary>
    /// Creates a DAP representation of a given <see cref="IVariable"/>.
    /// </summary>
    /// <param name="variable">The <see cref="IVariable"/>.</param>
    /// <param name="context">A context used when reading the variable's value.</param>
    /// <param name="evaluate">If true, <see cref="IVariable.Evaluate"/> will be called before reading the value.</param>
    /// <returns>A DAP <see cref="Variable"/> model.</returns>
    public static Variable GetAsProtocol(this IVariable variable, VariableContext context, bool evaluate = false)
    {
        if (evaluate)
            variable.Evaluate(context);

        string? address = null;
        if (variable is IAddressBackedVariable addressBackedVariable)
            address = FormattingUtils.FormatAddress(addressBackedVariable.GetAddress());

        return new Variable()
        {
            Name = variable.Name,
            Type = variable.Type,
            Value = variable.Get(context),
            NamedVariables = variable.Children?.Count,
            VariablesReference = variable.Reference,
            MemoryReference = address
        };
    }

    /// <summary>
    /// Creates a DAP 'Evaluate' response representation of a given <see cref="IVariable"/>.
    /// </summary>
    /// <param name="variable">The <see cref="IVariable"/>.</param>
    /// <param name="context">A context used when reading the variable's value.</param>
    /// <param name="evaluate">If true, <see cref="IVariable.Evaluate"/> will be called before reading the value.</param>
    /// <returns>A DAP <see cref="Variable"/> model.</returns>
    public static EvaluateResponse GetAsEvaluateResponse(this IVariable variable, VariableContext context,
        bool evaluate = false)
    {
        if (evaluate)
            variable.Evaluate(context);

        string? address = null;
        if (variable is IAddressBackedVariable addressBackedVariable)
            address = FormattingUtils.FormatAddress(addressBackedVariable.GetAddress());

        return new EvaluateResponse()
        {
            Type = variable.Type,
            Result = variable.Get(context),
            NamedVariables = variable.Children?.Count,
            VariablesReference = variable.Reference,
            MemoryReference = address
        };
    }

    /// <summary>
    /// Returns the length of this <see cref="DebuggerVariableType"/> in bytes.
    /// </summary>
    public static int GetSize(this DebuggerVariableType type)
    {
        return type switch
        {
            DebuggerVariableType.ByteU or DebuggerVariableType.ByteS or DebuggerVariableType.CharAscii => 1,
            DebuggerVariableType.ShortU or DebuggerVariableType.ShortS => 2,
            DebuggerVariableType.IntU or DebuggerVariableType.IntS => 4,
            DebuggerVariableType.LongU or DebuggerVariableType.LongS => 8,
            DebuggerVariableType.Float => 4,
            DebuggerVariableType.Double => 8,
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
        };
    }

    /// <summary>
    /// Returns the length of this <see cref="ExpressionValueType"/> in bytes.
    /// </summary>
    /// <remarks>
    /// For <see cref="ExpressionValueType.String"/> and <see cref="ExpressionValueType.Default"/>, -1 is returned.
    /// </remarks>
    public static int GetSize(this ExpressionValueType type)
    {
        return type switch
        {
            ExpressionValueType.ByteU or ExpressionValueType.ByteS => 1,
            ExpressionValueType.ShortU or ExpressionValueType.ShortS => 2,
            ExpressionValueType.IntU or ExpressionValueType.IntS => 4,
            ExpressionValueType.LongU or ExpressionValueType.LongS => 8,
            ExpressionValueType.Float => 4,
            ExpressionValueType.Double => 8,
            ExpressionValueType.String or ExpressionValueType.Default => -1,
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
        };
    }

    /// <summary>
    /// Returns a human-readable name of this <see cref="DebuggerVariableType"/>.
    /// </summary>
    public static string GetName(this DebuggerVariableType type)
    {
        return type switch
        {
            DebuggerVariableType.ByteU => "unsigned byte",
            DebuggerVariableType.ByteS => "byte",
            DebuggerVariableType.CharAscii => "char",
            DebuggerVariableType.ShortU => "unsigned short16",
            DebuggerVariableType.ShortS => "short16",
            DebuggerVariableType.IntU => "unsigned int32",
            DebuggerVariableType.IntS => "int32",
            DebuggerVariableType.LongU => "unsigned long64",
            DebuggerVariableType.LongS => "long64",
            DebuggerVariableType.Float => "float32",
            DebuggerVariableType.Double => "double64",
            _ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
        };
    }
}
