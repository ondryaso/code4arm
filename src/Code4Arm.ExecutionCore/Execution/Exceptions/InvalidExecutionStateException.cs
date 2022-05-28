// InvalidExecutionStateException.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidExecutionStateException : DebuggerException
{
    public InvalidExecutionStateException(ExecutionState state,
        Exception? innerException = null) : base(ExceptionCodes.InvalidExecutionStateId,
        ExceptionCodes.InvalidExecutionState,
        DebuggerExceptionType.InvalidRequest, string.Format(ExceptionMessages.InvalidExecutionState, state),
        innerException)
    {
    }

    public InvalidExecutionStateException(string description,
        Exception? innerException = null) : base(ExceptionCodes.InvalidExecutionStateId,
        ExceptionCodes.InvalidExecutionState,
        DebuggerExceptionType.InvalidRequest, description,
        innerException)
    {
    }
}
