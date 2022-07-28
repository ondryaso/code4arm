// IExecutionEngine.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.Unicorn.Abstractions;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

/// <summary>
/// Represents an execution engine that manages an emulation of a program.
/// The engine primarily provides methods that control the lifetime of the emulation (like starting it, stopping it
/// or settings breakpoints). Additional debugging features for inspecting the program's state are available in an
/// instance of <see cref="IDebugProvider"/> provided by <see cref="DebugProvider"/>.
/// </summary>
public interface IExecutionEngine : IDisposable
{
    /// <summary>
    /// The current state of this engine and its execution.
    /// </summary>
    ExecutionState State { get; }

    /// <summary>
    /// The currently loaded executable.
    /// </summary>
    IExecutableInfo? ExecutableInfo { get; }
    
    /// <summary>
    /// A provider of runtime information about the current execution.
    /// Null if no executable is loaded.
    /// </summary>
    IRuntimeInfo? RuntimeInfo { get; }
    
    /// <summary>
    /// A provider of debugging-related features.
    /// </summary>
    IDebugProvider DebugProvider { get; }
    
    /// <summary>
    /// A source locator that enables mapping between client-oriented <see cref="Source"/> instances and this engine's
    /// internal representations of sources.
    /// </summary>
    IDebugProtocolSourceLocator SourceLocator { get; }

    /// <summary>
    /// A <see cref="Task"/> representing the last started emulation step.
    /// </summary>
    Task? CurrentExecutionTask { get; }

    /// <summary>
    /// The Unicorn engine instance.
    /// </summary>
    IUnicorn Engine { get; }

    /// <summary>
    /// Text data written to this <see cref="TextWriter"/> are sent to the user as the output of the emulated program.
    /// </summary>
    TextWriter EmulatedOutput { get; }

    /// <summary>
    /// Blocks until the specified number of program input characters is received from the user.
    /// </summary>
    /// <param name="numberOfChars">Number of characters to read. If <see langword="null"/>, the whole contents
    /// of the input buffer will be returned after at least one character is received.</param>
    /// <returns>A string of the input characters.</returns>
    string WaitForEmulatedInput(int? numberOfChars);

    /// <summary>
    /// Blocks until a sequence of characters ending with a '\n' is received from the user.
    /// </summary>
    /// <returns>A line of text input.</returns>
    string WaitForEmulatedInputLine();

    /// <summary>
    /// Appends one character to (the end of) the emulated input buffer.
    /// </summary>
    /// <param name="c">The character to append.</param>
    void UngetEmulatedInputChar(char c);

    /// <summary>
    /// Loads an executable, maps emulated memory (for segments in the executable, stack and heap).
    /// </summary>
    /// <remarks>
    /// This method is NOT thread-safe and does NOT check the engine's state.
    /// </remarks>
    /// <param name="executable">An <see cref="Executable"/> object describing the executable.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>.
    Task LoadExecutable(Executable executable);

    /// <summary>
    /// Returns a program state feature.
    /// </summary>
    /// <typeparam name="TFeature">The feature type.</typeparam>
    /// <returns>An instance of the requested feature or <see langword="null"/> if no such feature is registered.</returns>
    /// <exception cref="ExecutableNotLoadedException">The requested feature may only be retrieved when an executable is loaded.</exception>
    TFeature? GetStateFeature<TFeature>() where TFeature : class, IExecutionStateFeature;

    /// <summary>
    /// Sets data breakpoints. They are identified by IDs previously retrieved using <see cref="IDebugProvider.GetDataBreakpointInfo(long,string)"/>
    /// for variables or <see cref="IDebugProvider.GetDataBreakpointInfo(string)"/> for expressions.
    /// </summary>
    IEnumerable<Breakpoint> SetDataBreakpoints(IEnumerable<DataBreakpoint> dataBreakpoints);

    /// <summary>
    /// Sets breakpoints and logpoints for positions (lines) in a given source.
    /// </summary>
    /// <remarks>
    /// There may always be only a single breakpoint set for a given instruction. When given a line that doesn't contain
    /// an instruction, the breakpoint will be set on the next following line with an instruction (or unverified if no
    /// instruction follows).
    /// </remarks>
    IEnumerable<Breakpoint> SetBreakpoints(Source file, IEnumerable<SourceBreakpoint> breakpoints);

    /// <summary>
    /// This is currently an empty operation because the engine always breaks on all exceptions.
    /// All returned breakpoints will be verified.
    /// </summary>
    IEnumerable<Breakpoint> SetExceptionBreakpoints(IEnumerable<string> filterIds);

    /// <summary>
    /// Sets <b>data breakpoints</b> for expressions. The engine currently doesn't support breaking on functions
    /// and VSC doesn't support expression data breakpoints so this is used instead.
    /// </summary>
    IEnumerable<Breakpoint> SetFunctionBreakpoints(IEnumerable<FunctionBreakpoint> functionBreakpoints);

    /// <summary>
    /// Sets breakpoints for given addresses.
    /// </summary>
    Task<IEnumerable<Breakpoint>> SetInstructionBreakpoints(IEnumerable<InstructionBreakpoint> instructionBreakpoints);

    /// <summary>
    /// (Re-)initializes the virtual memory from the loaded executable and starts an emulation step in another thread.
    /// If <paramref name="waitForLaunch"/> is true, the execution will not be started until <see cref="Launch"/>
    /// is called. 
    /// </summary>
    /// <remarks>
    /// Thread-safe.
    /// An executable must be loaded.
    /// The execution must be in the <see cref="ExecutionState.Ready"/> or <see cref="ExecutionState.Finished"/> state.
    /// If another thread starts execution after the initial state check, this method waits for a maximum of
    /// <paramref name="enterTimeout"/> ms for it to finish.
    /// A timeout set to the value of <see cref="ExecutionOptions.Timeout"/> is started before the thread is created.
    /// If the thread waits for the Launch event, this timeout may be triggered before Launch is called. 
    /// </remarks>
    /// <param name="debug">If true, debugging will be enabled.</param>
    /// <param name="enterTimeout">The maximum amount of time in ms this method waits for the end of the current execution.</param>
    /// <param name="waitForLaunch">If true, the execution will only being after <see cref="Launch"/> is called.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>.
    /// <exception cref="InvalidExecutionStateException">The execution is not ready or finished.</exception>
    Task InitLaunch(bool debug, int enterTimeout = Timeout.Infinite, bool waitForLaunch = true);

    /// <summary>
    /// Allows the previous call to <see cref="InitLaunch"/> to continue (if it was called with <c>waitForLaunch</c> set
    /// to <see langword="true"/>).
    /// </summary>
    /// <returns>A Task representing the asynchronous operation.</returns>
    Task Launch();

    /// <summary>
    /// Terminates the current execution (if it's running) and calls <see cref="InitLaunch"/> (with <c>waitForLaunch</c>
    /// set to <see langword="true"/>).
    /// Starts an emulation step in another thread.
    /// </summary>
    /// <remarks>
    /// Thread-safe.
    /// An executable must be loaded.
    /// Waits for the current execution to finish.
    /// </remarks>
    /// <param name="debug">If true, debugging will be enabled.</param>
    /// <param name="enterTimeout">The maximum amount of time in ms this method waits for the end of the current execution.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    /// <exception cref="ExecutableNotLoadedException">No executable is loaded.</exception>
    Task Restart(bool debug, int enterTimeout = Timeout.Infinite);

    /// <summary>
    /// Changes the program counter to a value described by <paramref name="targetId"/> previously retrieved using
    /// <see cref="IDebugProvider.GetGotoTargets(Code4Arm.ExecutionCore.Protocol.Models.Source,int,System.Nullable{int})"/>.
    /// No emulation step is performed.
    /// </summary>
    /// <remarks>
    /// Thread-safe.
    /// An executable must be loaded.
    /// The execution must be paused. If another thread starts execution after the initial state check, this method
    /// waits for a maximum of <paramref name="enterTimeout"/> ms for it to finish.
    /// Sends a 'Stopped' event and doesn't start another execution.
    /// </remarks>
    /// <param name="targetId">The goto target ID.</param>
    /// <param name="enterTimeout">The maximum amount of time in ms this method may wait for the end of the current execution.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    /// <exception cref="ExecutableNotLoadedException">No executable is loaded.</exception>
    /// <exception cref="InvalidExecutionStateException">The execution is not in a paused state.</exception>
    Task GotoTarget(long targetId, int enterTimeout = Timeout.Infinite);

    /// <summary>
    /// Continues a previously paused execution.
    /// Starts an emulation step in another thread.
    /// </summary>
    /// <remarks>
    /// Thread-safe.
    /// An executable must be loaded.
    /// The execution must be paused. If another thread starts execution after the initial state check, this method
    /// waits for a maximum of <paramref name="enterTimeout"/> ms for it to finish.
    /// </remarks>
    /// <param name="enterTimeout">The maximum amount of time in ms this method may wait for the end of the current execution.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    /// <exception cref="ExecutableNotLoadedException">No executable is loaded.</exception>
    /// <exception cref="InvalidExecutionStateException">The execution is not in a paused state.</exception>
    Task Continue(int enterTimeout = Timeout.Infinite);

    /// <summary>
    /// Applies the oldest available saved CPU state or the state at the closest previous breakpoint.
    /// No emulation step is performed.
    /// </summary>
    /// <remarks>
    /// <see cref="ExecutionOptions.StepBackMode"/> must not be <see cref="StepBackMode.None"/>.
    /// Thread-safe.
    /// An executable must be loaded.
    /// The execution must be paused. If another thread starts execution after the initial state check, this method
    /// waits for a maximum of <paramref name="enterTimeout"/> ms for it to finish.
    /// </remarks>
    /// <param name="enterTimeout">The maximum amount of time in ms this method may wait for the end of the current execution.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    /// <exception cref="ExecutableNotLoadedException">No executable is loaded.</exception>
    /// <exception cref="InvalidExecutionStateException">The execution is not in a paused state.</exception>
    /// <exception cref="StepBackNotEnabledException">Step back is not enabled or no more steps are saved.</exception>
    Task ReverseContinue(int enterTimeout = Timeout.Infinite);

    /// <summary>
    /// Executes a single instruction. If step back is enabled, captures the current CPU state before executing.
    /// The emulation step MAY or MAY NOT be performed on the caller's thread. 
    /// </summary>
    /// <remarks>
    /// Thread-safe.
    /// An executable must be loaded.
    /// The execution must be paused. If another thread starts execution after the initial state check, this method
    /// waits for a maximum of <paramref name="enterTimeout"/> ms for it to finish.
    /// </remarks>
    /// <param name="enterTimeout">The maximum amount of time in ms this method may wait for the end of the current execution.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    /// <exception cref="ExecutableNotLoadedException">No executable is loaded.</exception>
    /// <exception cref="InvalidExecutionStateException">The execution is not in a paused state.</exception>
    Task Step(int enterTimeout = Timeout.Infinite);

    /// <summary>
    /// Restores the newest saved CPU state.
    /// No emulation step is performed.
    /// </summary>
    /// <remarks>
    /// <see cref="ExecutionOptions.StepBackMode"/> must not be <see cref="StepBackMode.None"/>.
    /// Thread-safe.
    /// An executable must be loaded.
    /// The execution must be paused. If another thread starts execution after the initial state check, this method
    /// waits for a maximum of <paramref name="enterTimeout"/> ms for it to finish.
    /// </remarks>
    /// <param name="enterTimeout">The maximum amount of time in ms this method may wait for the end of the current execution.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    /// <exception cref="ExecutableNotLoadedException">No executable is loaded.</exception>
    /// <exception cref="InvalidExecutionStateException">The execution is not in a paused state.</exception>
    /// <exception cref="StepBackNotEnabledException">Step back is not enabled or no more steps are saved.</exception>
    Task StepBack(int enterTimeout = Timeout.Infinite);

    /// <summary>
    /// This is currently only a placeholder that calls <see cref="Step"/>.
    /// In the future, this will be used to support stepping out of functions.
    /// </summary>
    Task StepOut(int enterTimeout = Timeout.Infinite);

    /// <summary>
    /// Stops the current execution step, pausing the execution after the currently processed instruction.
    /// If the execution is not running, this is an empty operation.
    /// </summary>
    /// <remarks>
    /// Thread-safe.
    /// An executable must be loaded.
    /// </remarks>
    /// <returns>A Task representing the asynchronous operation.</returns>
    /// <exception cref="ExecutableNotLoadedException">No executable is loaded.</exception>
    Task Pause();

    /// <summary>
    /// Stops the execution.
    /// </summary>
    /// <remarks>
    /// Thread-safe.
    /// An executable must be loaded.
    /// The execution must NOT be in the <see cref="ExecutionState.Ready"/> or <see cref="ExecutionState.Finished"/> state.
    /// </remarks>
    /// <returns>A Task representing the asynchronous operation.</returns>
    /// <exception cref="ExecutableNotLoadedException">No executable is loaded.</exception>
    /// <exception cref="InvalidExecutionStateException">The execution is in the ready or finished state.</exception>
    Task Terminate();
}
