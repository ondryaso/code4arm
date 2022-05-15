// DebuggerException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class DebuggerException : Exception
{
    public int ErrorId { get; }
    public string ErrorMessage { get; }
    public DebuggerExceptionType ErrorType { get; }

    public DebuggerException(int id, string message, DebuggerExceptionType type,
        string description, Exception? innerException = null)
        : base(description, innerException)
    {
        ErrorId = id;
        ErrorMessage = message;
        ErrorType = type;
    }
}
