// ISyscallSimulator.cs
// Author: Ondřej Ondryáš

using Code4Arm.Unicorn.Abstractions;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public interface ISyscallSimulator
{
    int SyscallNumber { get; }
    void Run(IExecutionEngine engine);
}
