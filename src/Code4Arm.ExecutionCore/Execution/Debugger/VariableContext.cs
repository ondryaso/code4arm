﻿// VariableContext.cs
// Author: Ondřej Ondryáš

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

    public VariableContext(ExecutionEngine engine, CultureInfo cultureInfo, DebuggerOptions options,
        ExpressionValueFormat expressionValueFormat)
    {
        CultureInfo = cultureInfo;
        Engine = engine;
        Options = options;
        NumberFormat = expressionValueFormat == ExpressionValueFormat.Default
            ? options.VariableNumberFormat
            : (VariableNumberFormat)expressionValueFormat;

        if (expressionValueFormat == ExpressionValueFormat.Ieee)
            throw new ArgumentException("Cannot use the IEEE expression value format in VariableContext.",
                nameof(expressionValueFormat));
    }

    public VariableContext(ExecutionEngine engine, CultureInfo cultureInfo, DebuggerOptions options,
        VariableNumberFormat numberFormat)
    {
        CultureInfo = cultureInfo;
        Engine = engine;
        Options = options;
        NumberFormat = numberFormat;
    }

    public VariableContext(ExecutionEngine engine, CultureInfo cultureInfo, DebuggerOptions options,
        ValueFormat? valueFormat)
    {
        CultureInfo = cultureInfo;
        Engine = engine;
        Options = options;
        NumberFormat = (valueFormat is { Hex: true } ? VariableNumberFormat.Hex : options.VariableNumberFormat);
    }
}
