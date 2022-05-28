// EngineEvent.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Protocol.Events;
using MediatR;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

/// <summary>
/// A MediatR <see cref="IRequest"/> that carries a DAP Event dispatched from a given <see cref="IExecutionEngine"/>
/// instance.
/// </summary>
/// <typeparam name="TEvent">The type of the carried <see cref="IProtocolEvent"/>.</typeparam>
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
