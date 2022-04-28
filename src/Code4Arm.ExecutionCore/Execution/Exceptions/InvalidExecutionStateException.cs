// InvalidExecutionStateException.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidExecutionStateException : ExecutionEngineException
{
    public ExecutionState State { get; }

    public InvalidExecutionStateException(Guid executionId, string action, ExecutionState state)
        : base(executionId, $"Cannot perform '{action}' in execution state {state}.")
    {
        State = state;
    }

    public override string ErrorType => "invalidExecutionState";
}
