// ExecutionState.cs
// Author: Ondřej Ondryáš

namespace Armulator.ExecutionService.Execution.Abstractions;

public enum ExecutionState
{
    Ready,
    Running,
    WaitingForInput,
    Breakpoint,
    Exception,
    Ended
}
