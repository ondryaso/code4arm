// ExecutableNotLoadedException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class ExecutableNotLoadedException : ExecutionEngineException
{
    public ExecutableNotLoadedException(Guid? executionId, string action)
        : base(executionId, $"Cannot perform '{action}' because no executable is loaded in the execution engine.")
    {
    }

    public override string ErrorType => "executableNotLoaded";
}
