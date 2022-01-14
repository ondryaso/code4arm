// IProjectState.cs
// Author: Ondřej Ondryáš

using System.Numerics;

namespace Armulator.ExecutionService.Execution.Abstractions;

public interface IProjectState
{
    IRegisterFile<int> Registers { get; }
    IRegisterFile<BigInteger> VectorRegisters { get; }
    List<IBreakpoint> Breakpoints { get; }
}
