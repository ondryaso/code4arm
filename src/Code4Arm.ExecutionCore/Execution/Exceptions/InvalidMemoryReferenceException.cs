// InvalidMemoryReferenceException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidMemoryReferenceException : DebuggerException
{
    public InvalidMemoryReferenceException(string description = ExceptionMessages.InvalidMemoryReference,
        Exception? innerException = null) : base(ExceptionCodes.InvalidMemoryReferenceId, ExceptionCodes.InvalidMemoryReference,
        DebuggerExceptionType.InvalidRequest, description, innerException)
    {
    }
}
