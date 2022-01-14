// IExecutionContext.cs
// Author: Ondřej Ondryáš

using System.Numerics;

namespace Armulator.ExecutionService.Execution.Abstractions;

public interface IExecutionContext : IDisposable
{
    IProjectState InternalState { get; }
    ExecutionState ExecutionState { get; }
    IExecutionMemory Memory { get; }

    bool Ended { get; }

    IRegisterFile<int> Registers => this.InternalState.Registers;
    IRegisterFile<BigInteger> VectorRegisters => this.InternalState.VectorRegisters;
    List<IBreakpoint> Breakpoints => this.InternalState.Breakpoints;

    IBreakpoint? CurrentBreakpoint { get; }

    Stream Input { get; }
    Stream Output { get; }

    void Run();
    void Halt();
}
