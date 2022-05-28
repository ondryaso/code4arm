// ExecutionState.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Models;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

/// <summary>
/// Determines the possible states of an <see cref="IExecutionEngine"/>.
/// </summary>
public enum ExecutionState
{
    /// <summary>
    /// No <see cref="Executable"/> has been loaded, execution cannot be launched.
    /// </summary>
    Unloaded,

    /// <summary>
    /// An <see cref="Executable"/> has been loaded and it is waiting to be launched.
    /// </summary>
    Ready,

    /// <summary>
    /// The execution (emulation) is running.
    /// </summary>
    Running,

    /// <summary>
    /// The execution has been paused after a step, 'Goto' jump or explicit user-initiated pause.
    /// </summary>
    Paused,

    /// <summary>
    /// The execution has been paused after hitting a breakpoint.
    /// </summary>
    PausedBreakpoint,

    /// <summary>
    /// The execution has been paused after a runtime (in emulated CPU) exception occured.
    /// </summary>
    PausedException,

    /// <summary>
    /// The execution (emulation) has reached the end of the program and finished.
    /// </summary>
    Finished
}
