// DebuggerException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionService.Exceptions;

public class DebuggerException : Exception
{
    public string Code { get; }
    public long Id { get; }
    public string? FullMessageFormat { get; }
    public bool ShowUser { get; }
    public bool SendTelemetry { get; }
    public IDictionary<string, string>? Variables { get; init; }

    public DebuggerException(string code, long id, bool showUser = true, bool sendTelemetry = true)
        : this(code, id, null, showUser, sendTelemetry)
    {
    }

    public DebuggerException(string code, long id, string? fullMessage, bool showUser = true, bool sendTelemetry = true)
        : base($"Debugger exception '{code}' [{id}].")
    {
        Code = code;
        Id = id;
        ShowUser = showUser;
        SendTelemetry = sendTelemetry;
        FullMessageFormat = fullMessage;
    }
}
