// IVariable.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public interface IVariable
{
    string Name { get; }
    string? Type { get; }
    long Reference { get; }
    bool CanSet { get; }
    /// <summary>
    /// If true, the Evaluate() method of a parent variable should be called to make this variable's value.
    /// </summary>
    bool EvaluateParentForChildren { get; }
    IReadOnlyDictionary<string, IVariable>? Children { get; }

    void Evaluate(VariableContext context);
    string Get(VariableContext context);
    void Set(string value, VariableContext context);

    string GetEvaluated(VariableContext context)
    {
        this.Evaluate(context);

        return this.Get(context);
    }
}
