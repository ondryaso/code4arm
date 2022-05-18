// InvalidGotoTargetException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidGotoTargetException : DebuggerException
{
    public InvalidGotoTargetException(string description = ExceptionMessages.InvalidGotoTarget,
        Exception? innerException = null) : base(ExceptionCodes.InvalidGotoTargetId, ExceptionCodes.InvalidGotoTarget,
        DebuggerExceptionType.InvalidRequest, description, innerException)
    {
    }
}
