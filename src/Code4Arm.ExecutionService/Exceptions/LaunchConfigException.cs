// LaunchConfigException.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionService.Exceptions;

public class LaunchConfigException : DebuggerException
{
    public LaunchConfigException(string description, params object?[] args)
        : base(ExceptionCodes.LaunchConfigId, ExceptionCodes.LaunchConfig, DebuggerExceptionType.User,
            string.Format(description, args))
    {
    }
}
