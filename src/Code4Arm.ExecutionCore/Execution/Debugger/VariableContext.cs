// VariableContext.cs
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

using System.Globalization;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Protocol.Models;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public readonly struct VariableContext
{
    public readonly ExecutionEngine Engine;
    public readonly CultureInfo CultureInfo;
    public readonly DebuggerOptions Options;
    public readonly VariableNumberFormat NumberFormat;
    public readonly bool ForceSigned;

    public VariableContext(ExecutionEngine engine, CultureInfo cultureInfo, DebuggerOptions options,
        ExpressionValueFormat expressionValueFormat)
    {
        CultureInfo = cultureInfo;
        Engine = engine;
        Options = options;
        NumberFormat = expressionValueFormat == ExpressionValueFormat.Default
            ? options.VariableNumberFormat
            : (VariableNumberFormat)expressionValueFormat;
        ForceSigned = false;

        if (expressionValueFormat == ExpressionValueFormat.Ieee)
            throw new ArgumentException("Cannot use the IEEE expression value format in VariableContext.",
                nameof(expressionValueFormat));
    }

    public VariableContext(ExecutionEngine engine, CultureInfo cultureInfo, DebuggerOptions options,
        VariableNumberFormat numberFormat, bool forceSigned = false)
    {
        CultureInfo = cultureInfo;
        Engine = engine;
        Options = options;
        NumberFormat = numberFormat;
        ForceSigned = forceSigned;
    }

    public VariableContext(ExecutionEngine engine, CultureInfo cultureInfo, DebuggerOptions options,
        ValueFormat? valueFormat)
    {
        CultureInfo = cultureInfo;
        Engine = engine;
        Options = options;
        NumberFormat = (valueFormat is { Hex: true } ? VariableNumberFormat.Hex : options.VariableNumberFormat);        
        ForceSigned = false;
    }
}
