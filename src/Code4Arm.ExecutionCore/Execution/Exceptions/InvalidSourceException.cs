// InvalidSourceException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidSourceException : DebuggerException
{
    public InvalidSourceException(string description = ExceptionMessages.InvalidSource,
        Exception? innerException = null) : base(ExceptionCodes.InvalidSourceId, ExceptionCodes.InvalidSource,
        DebuggerExceptionType.InvalidRequest, description, innerException)
    {
    }
}
