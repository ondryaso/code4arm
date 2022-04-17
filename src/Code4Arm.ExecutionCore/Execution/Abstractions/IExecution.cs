// IExecution.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.Unicorn.Abstractions;
using OmniSharp.Extensions.DebugAdapter.Protocol.Models;
using OmniSharp.Extensions.DebugAdapter.Protocol.Requests;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public interface IExecution : IDisposable
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

    void SetDataBreakpoints(IEnumerable<DataBreakpoint> dataBreakpoints);
    void SetBreakpoints(SetBreakpointsArguments arguments);
    void SetFunctionBreakpoints(IEnumerable<FunctionBreakpoint> functionBreakpoints);
    void SetInstructionBreakpoints(IEnumerable<InstructionBreakpoint> instructionBreakpoints);

    ICodeStaticInfo CodeInfo { get; }
    IExecutableInfo ExecutableInfo { get; }
    ICodeExecutionInfo ExecutionInfo { get; }
    
    IUnicorn Engine { get; }

    Stream EmulatedInput { get; }
    Stream EmulatedOutput { get; }

    // remaps memory
    void Launch(bool debug);
    // terminates and launches
    void Restart(bool debug);
    void GotoTarget(int targetId);
    void Continue();
    void ReverseContinue();
    void Step();
    void StepBack();
    void StepOut();
    void Pause();
    void Terminate();
}
