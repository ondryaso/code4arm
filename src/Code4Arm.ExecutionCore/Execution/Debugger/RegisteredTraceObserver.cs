// RegisteredTraceObserver.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public readonly struct RegisteredTraceObserver : IEquatable<RegisteredTraceObserver>
{
    public readonly ITraceObserver Observer;
    public readonly long TraceId;

    public RegisteredTraceObserver(ITraceObserver observer, long traceId)
    {
        Observer = observer;
        TraceId = traceId;
    }

    public bool Equals(RegisteredTraceObserver other)
        => other.Observer == Observer && other.TraceId == TraceId;
    
    
}
