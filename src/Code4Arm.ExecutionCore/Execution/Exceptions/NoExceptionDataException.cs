// NoExceptionDataException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class NoExceptionDataException : DebuggerException
{
    public NoExceptionDataException(string description = ExceptionMessages.NoExceptionData,
        Exception? innerException = null) : base(ExceptionCodes.NoExceptionDataId, ExceptionCodes.NoExceptionData,
        DebuggerExceptionType.InvalidRequest, description, innerException)
    {
    }
}
