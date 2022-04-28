// EngineEvent.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Protocol.Events;
using MediatR;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public class EngineEvent<TEvent> : IRequest where TEvent : IProtocolEvent
{
    public IExecutionEngine Engine { get; }
    public TEvent Event { get; }

    public EngineEvent(IExecutionEngine engine, TEvent @event)
    {
        Engine = engine;
        Event = @event;
    }

}
