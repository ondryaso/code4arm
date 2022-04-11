// ISyscallSimulator.cs
// Author: Ondřej Ondryáš

using UnicornManaged;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public interface ISyscallSimulator
{
    int SyscallNumber { get; }
    void Run(Unicorn engine);
}
