// ExecutionState.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public enum ExecutionState
{
    Unloaded,
    Ready,
    Running,
    Paused,
    PausedBreakpoint,
    Finished,
    TerminatedManually,
    TerminatedException
}
