// IExecutionEngine.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.Unicorn.Abstractions;
using OmniSharp.Extensions.DebugAdapter.Protocol.Models;
using OmniSharp.Extensions.DebugAdapter.Protocol.Requests;

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

    ICodeStaticInfo? CodeInfo { get; }
    IExecutableInfo? ExecutableInfo { get; }
    ICodeExecutionInfo CodeExecutionInfo { get; }

    IReadOnlyList<MemorySegment> Segments { get; }

    IUnicorn Engine { get; }

    Stream EmulatedInput { get; }
    Stream EmulatedOutput { get; }

    void LoadExecutable(Executable executable);

    void SetDataBreakpoints(IEnumerable<DataBreakpoint> dataBreakpoints);
    void SetBreakpoints(SetBreakpointsArguments arguments);
    void SetFunctionBreakpoints(IEnumerable<FunctionBreakpoint> functionBreakpoints);
    void SetInstructionBreakpoints(IEnumerable<InstructionBreakpoint> instructionBreakpoints);

    // remaps memory
    Task Launch(bool debug, CancellationToken cancellationToken = default);

    // terminates and launches
    void Restart(bool debug, CancellationToken cancellationToken = default);
    void GotoTarget(int targetId);
    Task Continue(CancellationToken cancellationToken = default);
    Task ReverseContinue(CancellationToken cancellationToken = default);
    void Step();
    void StepBack();
    Task StepOut(CancellationToken cancellationToken = default);
    void Pause();
    void Terminate();
}
