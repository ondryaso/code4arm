// InvalidSourceException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidSourceException : ExecutionEngineException
{
    public override string ErrorType => "invalidSourceReference";

    public InvalidSourceException(Guid? executionId, string action)
        : base(executionId,
            $"Cannot perform '{action}' because the provided Source object is not valid in the current context (invalid reference or adapter data).")
    {
    }
}
