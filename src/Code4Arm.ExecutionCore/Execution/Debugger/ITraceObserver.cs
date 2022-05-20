// ITraceObserver.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public interface ITraceObserver
{
    VariableContext GetTraceTriggerContext();
    void TraceTriggered(long traceId);
}

public interface ITraceObserver<in TTracedValue> : ITraceObserver
{
    void TraceTriggered(long traceId, TTracedValue oldValue, TTracedValue newValue);
}

public interface IFormattedTraceObserver : ITraceObserver<string?>
{
}
