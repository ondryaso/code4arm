// Extensions.cs
// Author: Ondřej Ondryáš

using System.Reflection;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public static class Extensions
{
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
