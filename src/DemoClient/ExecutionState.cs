// ExecutionState.cs
// Author: Ondřej Ondryáš

namespace DemoClient;

public enum ExecutionState
{
    Ready,
    Running,
    WaitingForInput,
    Breakpoint,
    Exception,
    Ended
}
