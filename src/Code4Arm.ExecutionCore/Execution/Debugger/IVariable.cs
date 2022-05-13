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
    /// If true, this child variable is a view over its parent's data.
    /// The Evaluate() method of a parent variable will be called to make this variable's value.
    /// When setting the variable, the whole parent tree should be updated (the protocol doesn't support this though).
    /// </summary>
    bool IsViewOfParent { get; }
    IReadOnlyDictionary<string, IVariable>? Children { get; }
    IVariable? Parent { get; }

    void Evaluate(VariableContext context);
    string Get(VariableContext context);
    void Set(string value, VariableContext context);

    string GetEvaluated(VariableContext context)
    {
        this.Evaluate(context);

        return this.Get(context);
    }
}
