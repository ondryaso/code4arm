// ExceptionCodes.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public static class ExceptionCodes
{
    public const int UnexpectedErrorId = 1000;
    public const string UnexpectedError = "unexpectedError";

    public const string InvalidExpression = "invalidExpression";
    public const int InvalidExpressionId = 100;

    public const string InvalidVariable = "invalidVariable";
    public const int InvalidVariableId = 101;

    public const string ExecutableNotLoaded = "executableNotLoaded";
    public const int ExecutableNotLoadedId = 102;

    public const int InvalidSourceId = 103;
    public const string InvalidSource = "invalidSource";

    public const int NotInitializedId = 104;
    public const string NotInitialized = "notInitialized";

    public const int ConfigurationId = 105;
    public const string Configuration = "configuration";

    public const int InvalidVariableFormatId = 106;
    public const string InvalidVariableFormat = "invalidFormat";

    public const int NoExceptionDataId = 107;
    public const string NoExceptionData = "noExceptionData";

    public const int StepBackNotEnabledId = 108;
    public const string StepBackNotEnabled = "stepbackNotEnabled";

    public const int InvalidGotoTargetId = 109;
    public const string InvalidGotoTarget = "invalidTarget";
}
