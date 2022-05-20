// UIntBackedTraceable.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

/// <summary>
/// Provides common functionality for traceables that watch over an <see langword="uint"/> value.
/// The traceable may operate both in stepped and hooked mode.
/// Derived classes should call <see cref="SetTrace"/> after capturing the watched value.
/// This traceable supports typed <see cref="ITraceObserver{TTargetValue}"/> observers for <see langword="uint"/> type.
/// </summary>
public abstract class UIntBackedTraceable : ITraceable<uint>
{
    private readonly List<RegisteredTraceObserver> _traceObservers = new();
    private uint _traceValue;

    public abstract bool NeedsExplicitEvaluationAfterStep { get; }
    public abstract bool CanPersist { get; }
    protected bool HasObservers => _traceObservers.Count != 0;
    protected abstract string Format(uint value, VariableContext context);

    protected void SetTrace(uint newValue, bool notify = true)
    {
        if (_traceValue == newValue)
            return;

        if (notify && _traceObservers.Count != 0)
        {
            foreach (var traceObserver in _traceObservers)
            {
                var observer = traceObserver.Observer;
                var context = observer.GetTraceTriggerContext();

                switch (observer)
                {
                    case IFormattedTraceObserver formattedObserver:
                        formattedObserver.TraceTriggered(traceObserver.TraceId, this.Format(_traceValue, context),
                            this.Format(newValue, context));

                        break;
                    case ITraceObserver<uint> uintObserver:
                        uintObserver.TraceTriggered(traceObserver.TraceId, _traceValue, newValue);

                        break;
                    default:
                        observer.TraceTriggered(traceObserver.TraceId);

                        break;
                }
            }
        }

        _traceValue = newValue;
    }

    public virtual void InitTrace(ExecutionEngine engine, ITraceObserver observer, long traceId)
    {
        _traceObservers.Add(new RegisteredTraceObserver(observer, traceId));
    }

    public virtual void InitTrace(ExecutionEngine engine, ITraceObserver<uint> observer, long traceId)
    {
        this.InitTrace(engine, (ITraceObserver)observer, traceId);
    }

    public abstract void TraceStep(ExecutionEngine engine);

    public virtual void StopTrace(ExecutionEngine engine, ITraceObserver observer)
    {
        _traceObservers.Remove(_traceObservers.Find(t => t.Observer == observer));
    }
}
