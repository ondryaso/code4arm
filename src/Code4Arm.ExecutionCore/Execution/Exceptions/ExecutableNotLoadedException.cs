// ExecutableNotLoadedException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class ExecutableNotLoadedException : DebuggerException
{
    public ExecutableNotLoadedException(string description = ExceptionMessages.ExecutableNotLoaded,
        Exception? innerException = null) : base(ExceptionCodes.ExecutableNotLoadedId,
        ExceptionCodes.ExecutableNotLoaded,
        DebuggerExceptionType.InvalidRequest, description, innerException)
    {
    }
}
