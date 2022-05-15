// InvalidVariableException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidVariableException : DebuggerException
{
    public InvalidVariableException(string description = ExceptionMessages.InvalidVariable,
        Exception? innerException = null) : base(ExceptionCodes.InvalidVariableId, ExceptionCodes.InvalidVariable,
        DebuggerExceptionType.InvalidRequest, description, innerException)
    {
    }
}
