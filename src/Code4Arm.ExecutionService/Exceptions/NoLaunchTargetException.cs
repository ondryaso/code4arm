// NoLaunchTargetException.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionService.Exceptions;

public class NoLaunchTargetException : DebuggerException
{
    public NoLaunchTargetException(string description = ExceptionMessages.NoLaunchTarget)
        : base(ExceptionCodes.NoLaunchTargetId, ExceptionCodes.NoLaunchTarget,
            DebuggerExceptionType.User, description)
    {
    }
}
