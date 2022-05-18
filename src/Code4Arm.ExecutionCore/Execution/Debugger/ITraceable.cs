// ITraceable.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public interface ITraceable
{
    bool RequiresPerStepEvaluation { get; }

    void InitTrace(ExecutionEngine engine, ITraceObserver observer, long traceId);
    void TraceStep(ExecutionEngine engine);
    void StopTrace(ExecutionEngine engine);
}
