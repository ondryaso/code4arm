// InvalidExpressionException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidExpressionException : DebuggerException
{
    public InvalidExpressionException(string description = ExceptionMessages.InvalidExpression,
        Exception? innerException = null) : base(ExceptionCodes.InvalidExpressionId,
        ExceptionCodes.InvalidExpression, DebuggerExceptionType.UserImplicit, description, innerException)
    {
    }
}
