// InvalidVariableFormatException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidVariableFormatException : DebuggerException
{
    public InvalidVariableFormatException(string description = ExceptionMessages.InvalidVariableFormat,
        Exception? innerException = null) : base(ExceptionCodes.InvalidVariableFormatId,
        ExceptionCodes.InvalidVariableFormat, DebuggerExceptionType.UserImplicit, description, innerException)
    {
    }
}
