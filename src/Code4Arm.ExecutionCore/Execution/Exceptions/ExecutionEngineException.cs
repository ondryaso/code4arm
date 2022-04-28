// ExecutionEngineException.cs
// Author: Ondřej Ondryáš

using System.Runtime.Serialization;

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public abstract class ExecutionEngineException : Exception
{
    public Guid? ExecutionId { get; }
    public abstract string ErrorType { get; }

    protected ExecutionEngineException()
    {
    }

    protected ExecutionEngineException(string? message) : base(message)
    {
    }

    protected ExecutionEngineException(string? message, Exception? innerException)
        : base(message, innerException)
    {
    }

    protected ExecutionEngineException(Guid? executionId)
    {
        ExecutionId = executionId;
    }

    protected ExecutionEngineException(Guid? executionId, string? message) : base(message)
    {
        ExecutionId = executionId;
    }

    protected ExecutionEngineException(Guid? executionId, string? message, Exception? innerException)
        : base(message, innerException)
    {
        ExecutionId = executionId;
    }
}
