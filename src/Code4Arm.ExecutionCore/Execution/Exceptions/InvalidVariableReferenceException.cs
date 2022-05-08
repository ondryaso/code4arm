// InvalidVariableReferenceException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidVariableReferenceException : ExecutionEngineException
{
    public override string ErrorType => "invalidVariableReference";
}
