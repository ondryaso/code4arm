// InvalidValueException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidValueException : ExecutionEngineException
{
    public override string ErrorType => "invalidValue";
}
