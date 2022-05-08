// ProtocolEventAttribute.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Protocol.Events;

[AttributeUsage(AttributeTargets.Class)]
public class ProtocolEventAttribute : Attribute
{
    public string EventName { get; }
    public bool IsEmpty { get; }

    public ProtocolEventAttribute(string eventName, bool isEmpty = false)
    {
        EventName = eventName;
        IsEmpty = isEmpty;
    }
}
