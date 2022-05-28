// IFunctionSimulator.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public interface IFunctionSimulator
{
    string Name { get; }
    void Run(IExecutionEngine engine);
}
