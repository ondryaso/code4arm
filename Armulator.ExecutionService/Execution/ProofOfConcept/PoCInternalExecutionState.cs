// PoCInternalExecutionState.cs
// Author: Ondřej Ondryáš

using System.Numerics;
using Armulator.ExecutionService.Execution.Abstractions;
using UnicornManaged;

namespace Armulator.ExecutionService.Execution.ProofOfConcept;

internal class PoCInternalExecutionState : IProjectState
{
    private readonly PoCExecutionContext _ctx;
    private readonly Unicorn _unicorn;
    private readonly PoCExecutionRegisters _registers;
    private readonly List<PoCBreakpoint> _breakpoints;

    public PoCInternalExecutionState(PoCExecutionContext ctx)
    {
        _ctx = ctx;
        _unicorn = ctx.Unicorn;
        _registers = new PoCExecutionRegisters(ctx.Unicorn);
        _breakpoints = ctx.Project.PoCInitialState.PoCBreakpoints != null
            ? new List<PoCBreakpoint>(ctx.Project.PoCInitialState.PoCBreakpoints)
            : new List<PoCBreakpoint>();
    }

    public IRegisterFile<int> Registers => _registers;
    public IRegisterFile<BigInteger> VectorRegisters => throw new NotImplementedException();
    public IEnumerable<IBreakpoint> Breakpoints => _breakpoints;
}
