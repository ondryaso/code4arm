// ITraceable.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

/// <summary>
/// Represents a traceable object that notifies its observers of changes of the traced field.
/// This traceable only provides information about change but not about the underlying values.
/// </summary>
public interface ITraceable
{
    /// <summary>
    /// If true, <see cref="TraceStep"/> must be called after each instruction to update the state of this traceable. 
    /// </summary>
    bool NeedsExplicitEvaluationAfterStep { get; }
    
    /// <summary>
    /// Determines whether this traceable may be persisted across debug sessions.
    /// </summary>
    bool CanPersist { get; }

    /// <summary>
    /// Registers an observer for this traceable and initializes it, if no observers were registered before.
    /// </summary>
    /// <param name="engine">The execution engine.</param>
    /// <param name="observer">The traceable observer.</param>
    /// <param name="traceId">A numeric identifier specific to the registering observer.</param>
    void InitTrace(ExecutionEngine engine, ITraceObserver observer, long traceId);
    
    /// <summary>
    /// Called to update the state of this traceable.
    /// Only should be called if <see cref="NeedsExplicitEvaluationAfterStep"/> is true.
    /// </summary>
    /// <param name="engine">The execution engine.</param>
    void TraceStep(ExecutionEngine engine);
    
    /// <summary>
    /// Removes an observer from this traceable. If no observers are left, stops it altogether.
    /// </summary>
    /// <param name="engine">The execution engine.</param>
    /// <param name="observer">The traceable observer.</param>
    void StopTrace(ExecutionEngine engine, ITraceObserver observer);
}

/// <summary>
/// Represents a typed traceable object that notifies its typed observers of changes of the traced field.
/// </summary>
/// <typeparam name="TTracedValue">The value of the traced field.</typeparam>
public interface ITraceable<out TTracedValue> : ITraceable
{
    /// <summary>
    /// Registers a typed observer for this traceable and initializes it, if no observers were registered before.
    /// </summary>
    /// <remarks>
    /// It is expected that typed observers are only notified once and using the typed value, even if they register using
    /// the untyped equivalent of this method.
    /// </remarks>
    /// <param name="engine">The execution engine.</param>
    /// <param name="observer">The typed traceable observer.</param>
    /// <param name="traceId">A numeric identifier specific to the registering observer.</param>
    void InitTrace(ExecutionEngine engine, ITraceObserver<TTracedValue> observer, long traceId);
}
