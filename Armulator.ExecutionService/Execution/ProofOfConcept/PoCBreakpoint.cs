// PoCBreakpoint.cs
// Author: Ondřej Ondryáš

using Armulator.ExecutionService.Execution.Abstractions;

namespace Armulator.ExecutionService.Execution.ProofOfConcept;

public class PoCBreakpoint : IBreakpoint
{
    public int Line { get; set; }
    public bool IsException { get; set; }
}
