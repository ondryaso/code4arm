// InvalidMemoryOperationException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidMemoryOperationException : DebuggerException
{
    public InvalidMemoryOperationException(string description,
        Exception? innerException = null) : base(ExceptionCodes.InvalidMemoryOperationId,
        ExceptionCodes.InvalidMemoryOperation,
        DebuggerExceptionType.UserImplicit, description, innerException)
    {
    }
}
