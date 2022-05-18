// ITraceObserver.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public interface ITraceObserver
{
    void TraceTriggered(long traceId);
}
