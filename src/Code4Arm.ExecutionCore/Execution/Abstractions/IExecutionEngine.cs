// IExecutionEngine.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.Unicorn.Abstractions;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public interface IExecutionEngine : IDisposable
{
    ExecutionState State { get; }

    IExecutableInfo? ExecutableInfo { get; }
    IRuntimeInfo? RuntimeInfo { get; }
    IDebugProvider DebugProvider { get; }
    IDebugProtocolSourceLocator SourceLocator { get; }

    Task? CurrentExecutionTask { get; }

    IUnicorn Engine { get; }

    TextWriter EmulatedOutput { get; }
    string WaitForEmulatedInput(int? numberOfChars);
    string WaitForEmulatedInputLine();
    void UngetEmulatedInputChar(char c);
    
    Task LoadExecutable(Executable executable);

    TFeature? GetStateFeature<TFeature>() where TFeature : class, IExecutionStateFeature;

    IEnumerable<Breakpoint> SetDataBreakpoints(IEnumerable<DataBreakpoint> dataBreakpoints);
    IEnumerable<Breakpoint> SetBreakpoints(Source file, IEnumerable<SourceBreakpoint> breakpoints);
    IEnumerable<Breakpoint> SetExceptionBreakpoints(IEnumerable<string> filterIds);
    IEnumerable<Breakpoint> SetFunctionBreakpoints(IEnumerable<FunctionBreakpoint> functionBreakpoints);
    Task<IEnumerable<Breakpoint>> SetInstructionBreakpoints(IEnumerable<InstructionBreakpoint> instructionBreakpoints);

    /// <summary>
    /// (Re-)initializes the virtual memory from the loaded executable and starts the execution thread.
    /// If <paramref name="waitForLaunch"/> is true, the execution will not be started until <see cref="Launch"/>
    /// is called. This method is thread-safe (it will wait for <see cref="enterTimeout"/> ms if the execution is
    /// currently running).
    /// </summary>
    /// <remarks>
    /// A timeout set to the value of <see cref="ExecutionOptions.Timeout"/> is started before the thread is created.
    /// If the thread waits for the Launch event, this timeout may be triggered before Launch is called. 
    /// </remarks>
    /// <param name="debug">If true, debugging will be enabled.</param>
    /// <param name="enterTimeout">The maximum amount of time in ms this method waits for the end of the current execution.</param>
    /// <param name="waitForLaunch">If true, the execution will only being after <see cref="Launch"/> is called.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    Task InitLaunch(bool debug, int enterTimeout = Timeout.Infinite, bool waitForLaunch = true);

    Task Launch();

    // terminates and launches
    Task Restart(bool debug, int enterTimeout = Timeout.Infinite);
    Task GotoTarget(long targetId, int enterTimeout = Timeout.Infinite);
    Task Continue(int enterTimeout = Timeout.Infinite);
    Task ReverseContinue(int enterTimeout = Timeout.Infinite);
    Task Step(int enterTimeout = Timeout.Infinite);
    Task StepBack(int enterTimeout = Timeout.Infinite);
    Task StepOut(int enterTimeout = Timeout.Infinite);
    Task Pause();
    Task Terminate();
}
