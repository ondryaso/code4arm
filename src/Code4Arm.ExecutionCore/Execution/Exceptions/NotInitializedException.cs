// NotInitializedException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class NotInitializedException : DebuggerException
{
    public NotInitializedException(string description = ExceptionMessages.NotInitialized,
        Exception? innerException = null) : base(ExceptionCodes.NotInitializedId, ExceptionCodes.NotInitialized,
        DebuggerExceptionType.InvalidRequest, description, innerException)
    {
    }
}
