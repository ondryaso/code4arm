// ServiceCollectionExtensions.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Protocol.Events;
using Code4Arm.ExecutionService.RequestHandlers;
using MediatR;

namespace Code4Arm.ExecutionService.Extensions;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds transient services for <see cref="IRequestHandler{TRequest,TResponse}"/> for <see cref="EngineEvent{TEvent}"/>
    /// requests for all classes implementing <see cref="IProtocolEvent"/> in a given assembly. These services are implemented
    /// by <see cref="EngineEventRequestHandler{TEvent,THub}"/>. 
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to add the services to.</param>
    /// <param name="eventsAssembly">Any type in the assembly that events should be loaded from.</param>
    public static void AddProtocolEventHandlers<THub>(this IServiceCollection services, Type eventsAssembly)
    {
        var eventBase = typeof(IProtocolEvent);
        var eventTypes = eventsAssembly.Assembly.GetTypes().Where(t => t.IsAssignableTo(eventBase));

        var engineEventBase = typeof(EngineEvent<>);
        var requestHandlerBase = typeof(IRequestHandler<,>);
        var unit = typeof(Unit);
        var handlerBase = typeof(EngineEventRequestHandler<,>);
        var hubType = typeof(THub);

        foreach (var eventType in eventTypes)
        {
            var engineEvent = engineEventBase.MakeGenericType(eventType);
            var iRequestHandlerType = requestHandlerBase.MakeGenericType(engineEvent, unit);
            var eeRequestHandlerType = handlerBase.MakeGenericType(eventType, hubType);
            services.AddTransient(iRequestHandlerType, eeRequestHandlerType);
        }
    }

    public static void AddFunctionSimulators(this IServiceCollection services)
    {
        var coreAssembly = typeof(ExecutionEngine).Assembly;
        var simBase = typeof(IFunctionSimulator);
        var simulators = coreAssembly.GetTypes().Where(t => t.IsAssignableTo(simBase) && t.IsClass);

        foreach (var simulator in simulators)
        {
            services.AddTransient(simBase, simulator);
        }
    }
}
