// Extensions.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Protocol.Models;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public static class Extensions
{
    public static Variable GetAsProtocol(this IVariable variable, VariableContext context, bool evaluate = false)
    {
        if (evaluate)
            variable.Evaluate(context);

        return new Variable()
        {
            Name = variable.Name,
            Type = variable.Type,
            Value = variable.Get(context),
            NamedVariables = variable.Children?.Count,
            VariablesReference = variable.Reference
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
