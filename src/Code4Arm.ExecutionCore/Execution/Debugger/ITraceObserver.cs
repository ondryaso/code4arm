// ITraceObserver.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public interface ITraceObserver
{
    VariableContext GetTraceTriggerContext();
    void TraceTriggered(long traceId, string? oldValue, string? newValue);
}
