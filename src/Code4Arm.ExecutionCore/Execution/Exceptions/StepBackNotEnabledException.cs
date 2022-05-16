// StepBackNotEnabledException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class StepBackNotEnabledException : DebuggerException
{
    public StepBackNotEnabledException(string description = ExceptionMessages.StepBackNotEnabled,
        Exception? innerException = null) : base(ExceptionCodes.StepBackNotEnabledId, ExceptionCodes.StepBackNotEnabled,
        DebuggerExceptionType.Log, description, innerException)
    {
    }
}
