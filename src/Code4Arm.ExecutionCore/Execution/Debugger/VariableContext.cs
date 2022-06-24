// VariableContext.cs
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
