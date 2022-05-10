// InvalidExpression.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class InvalidExpressionException : ExecutionEngineException
{
    public override string ErrorType => "invalidExpression";

    public InvalidExpressionException()
        : base("Invalid expression.")
    {
    }
}
