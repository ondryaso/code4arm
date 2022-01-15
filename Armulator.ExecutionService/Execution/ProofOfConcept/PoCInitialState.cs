// PoCInitialState.cs
// Author: Ondřej Ondryáš

using System.Numerics;
using Armulator.ExecutionService.Execution.Abstractions;

namespace Armulator.ExecutionService.Execution.ProofOfConcept;

public class PoCInitialState : IProjectState
{
    public IRegisterFile<int> Registers => PoCRegisters;
    public IRegisterFile<BigInteger> VectorRegisters => throw new NotImplementedException();
    public IEnumerable<IBreakpoint> Breakpoints { get; }

    internal readonly List<PoCBreakpoint>? PoCBreakpoints;
    internal readonly PoCInitialRegisterFile<int> PoCRegisters;

    public PoCInitialState(PoCInitialRegisterFile<int> initialPoCRegisters, List<PoCBreakpoint>? initialBreakpoints)
    {
        PoCRegisters = initialPoCRegisters;
        if (initialBreakpoints != null)
        {
            PoCBreakpoints = new List<PoCBreakpoint>(initialBreakpoints);
            PoCBreakpoints.Sort((a, b) => a.Line - b.Line);
        }
        
        this.Breakpoints = PoCBreakpoints ?? Enumerable.Empty<IBreakpoint>();
    }

    public PoCInitialState()
    {
        PoCRegisters = new PoCInitialRegisterFile<int>();
        this.Breakpoints = Enumerable.Empty<IBreakpoint>();
    }
}
