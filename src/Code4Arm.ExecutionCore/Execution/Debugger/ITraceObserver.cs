// ITraceObserver.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

/// <summary>
/// An observer for traceable changes.
/// </summary>
public interface ITraceObserver
{
    /// <summary>
    /// Creates a <see cref="VariableContext"/> used by the traceables to format the values.
    /// </summary>
    VariableContext GetTraceTriggerContext();
    
    /// <summary>
    /// Called by the traceables to notify that their values have changed.
    /// </summary>
    /// <param name="traceId">The observer-specific identifier the observer has registered itself with.</param>
    void TraceTriggered(long traceId);
}

/// <summary>
/// A typed observer for typed traceable changes.
/// </summary>
/// <typeparam name="TTracedValue">The value of the traced field.</typeparam>
public interface ITraceObserver<in TTracedValue> : ITraceObserver
{
    /// <summary>
    /// Called by the traceables to notify that their values have changed.
    /// </summary>
    /// <remarks>
    /// It is expected that typed observers are only notified once and using the typed value, even if they register using
    /// the untyped equivalent of this method. However, if the observer is also a <see cref="IFormattedTraceObserver"/>,
    /// only its <see cref="TraceTriggered"/> method will be called.
    /// </remarks>
    /// <param name="traceId">The observer-specific identifier the observer has registered itself with.</param>
    /// <param name="oldValue">The previous value of the traced field.</param>
    /// <param name="newValue">The new value of the traced field.</param>
    void TraceTriggered(long traceId, TTracedValue oldValue, TTracedValue newValue);
}

/// <summary>
/// An observer typed with <see cref="string"/> that receives trace triggered events with formatted values of the
/// traced field.
/// </summary>
public interface IFormattedTraceObserver : ITraceObserver<string?>
{
}
