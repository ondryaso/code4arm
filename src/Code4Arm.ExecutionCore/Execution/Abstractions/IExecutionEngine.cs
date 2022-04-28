// IExecutionEngine.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.Unicorn.Abstractions;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public interface IExecutionEngine : IDisposable
{
    /// <summary>
    /// Controls the ability of this execution context to store CPU context after executing instructions and to step back.
    /// </summary>
    StepBackMode StepBackMode { get; set; }

    /// <summary>
    /// Controls whether writes to memory should be tracked when saving step contexts and reverted when stepping back.
    /// </summary>
    bool EnableStepBackMemoryCapture { get; set; }

    /// <summary>
    /// Controls whether registers can be used in data breakpoints.
    /// </summary>
    bool EnableRegisterDataBreakpoints { get; set; }

    ExecutionState State { get; }

    IExecutableInfo? ExecutableInfo { get; }
    IRuntimeInfo? RuntimeInfo { get; }
    IDebugProvider DebugProvider { get; }

    IUnicorn Engine { get; }

    Stream EmulatedInput { get; }
    Stream EmulatedOutput { get; }

    Task LoadExecutable(Executable executable);

    IEnumerable<Breakpoint> SetDataBreakpoints(IEnumerable<DataBreakpoint> dataBreakpoints);
    IEnumerable<Breakpoint> SetBreakpoints(Source file, IEnumerable<SourceBreakpoint> breakpoints);
    IEnumerable<Breakpoint> SetExceptionBreakpoints(IEnumerable<string> filterIds);
    IEnumerable<Breakpoint> SetFunctionBreakpoints(IEnumerable<FunctionBreakpoint> functionBreakpoints);
    IEnumerable<Breakpoint> SetInstructionBreakpoints(IEnumerable<InstructionBreakpoint> instructionBreakpoints);

    // remaps memory
    Task Launch(bool debug, CancellationToken cancellationToken = default, int timeout = Timeout.Infinite);

    // terminates and launches
    Task Restart(bool debug, CancellationToken cancellationToken = default);
    Task GotoTarget(long targetId);
    Task Continue(CancellationToken cancellationToken = default);
    Task ReverseContinue(CancellationToken cancellationToken = default);
    Task Step();
    Task StepBack();
    Task StepOut(CancellationToken cancellationToken = default);
    Task Pause();
    Task Terminate();
}
