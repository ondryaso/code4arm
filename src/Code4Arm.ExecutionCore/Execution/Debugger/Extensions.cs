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
}
