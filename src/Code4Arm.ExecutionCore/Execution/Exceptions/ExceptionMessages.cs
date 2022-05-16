// ExceptionMessages.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public static class ExceptionMessages
{
    public const string InvalidExpression = "Invalid expression.";
    public const string InvalidVariable = "Invalid variable reference.";
    public const string ExecutableNotLoaded = "No executable loaded.";
    public const string InvalidSource = "Invalid source reference.";
    public const string NotInitialized = "The debugger is not initialized. Issue an Initialize request first.";
    public const string InvalidVariableFormat = "Invalid input format.";
    public const string NoExceptionData = "No exception data found.";
    public const string StepBackNotEnabled = "Stepping back is not possible in the current context.";
}
