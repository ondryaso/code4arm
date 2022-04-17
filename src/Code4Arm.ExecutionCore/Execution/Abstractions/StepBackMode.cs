// StepBackMode.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public enum StepBackMode
{
    /// <summary>
    /// Disables step back completely.
    /// </summary>
    NoStepBack,

    /// <summary>
    /// Step back is only active when execution is stopped and its history is kept until execution is resumed.
    /// </summary>
    AfterBreakpoint,

    /// <summary>
    /// Step back can only be done once.
    /// </summary>
    LastStepOnly,
    
    /// <summary>
    /// The context is saved after each executed instruction.
    /// </summary>
    All
}
