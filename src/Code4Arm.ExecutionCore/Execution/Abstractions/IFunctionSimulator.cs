// IFunctionSimulator.cs
// Author: Ondřej Ondryáš

using Code4Arm.Unicorn.Abstractions;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public interface IFunctionSimulator
{
    string Name { get; }
    void Run(IExecutionEngine engine);
}
