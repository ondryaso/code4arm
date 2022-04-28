// EventNameAttribute.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Protocol.Events;

[AttributeUsage(AttributeTargets.Class)]
public class EventNameAttribute : Attribute
{
    public string EventName { get; }

    public EventNameAttribute(string eventName)
    {
        EventName = eventName;
    }
}
