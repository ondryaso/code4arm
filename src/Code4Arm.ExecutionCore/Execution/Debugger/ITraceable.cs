// ITraceable.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public interface ITraceable
{
    bool NeedsExplicitEvaluationAfterStep { get; }
    bool CanPersist { get; }

    void InitTrace(ExecutionEngine engine, ITraceObserver observer, long traceId);
    void TraceStep(ExecutionEngine engine);
    void StopTrace(ExecutionEngine engine, ITraceObserver observer);
}

public interface ITraceable<out TTracedValue> : ITraceable
{
    void InitTrace(ExecutionEngine engine, ITraceObserver<TTracedValue> observer, long traceId);
}
