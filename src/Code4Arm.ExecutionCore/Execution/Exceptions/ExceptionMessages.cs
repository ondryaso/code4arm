// ExceptionMessages.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public static class ExceptionMessages
{
    public const string InvalidExpression = "Invalid expression.";
    public const string InvalidExpressionTop = "Invalid expression: the general syntax is (type)expression:format.";
    public const string InvalidExpressionTypeSpecifier = "Invalid value type specifier.";
    public const string InvalidExpressionFormatSpecifier = "Invalid value format specifier.";
    public const string InvalidExpressionAddressing = "Invalid addressing expression: the general syntax is (type) [ Rx/address/symbol, Roffset/offset_value, shift shift_value ] :format";
    
    public const string InvalidVariable = "Invalid variable reference.";
    public const string ExecutableNotLoaded = "No executable loaded.";
    public const string InvalidSource = "Invalid source reference.";
    public const string NotInitialized = "The debugger is not initialized. Issue an Initialize request first.";
    public const string InvalidVariableFormat = "Invalid input format.";
    public const string NoExceptionData = "No exception data found.";
    public const string StepBackNotEnabled = "Stepping back is not possible in the current context.";
    public const string InvalidGotoTarget = "Invalid jump target address.";
    public const string InvalidMemoryReference = "Invalid memory reference (address).";
    public const string InvalidMemoryRead = "Invalid memory read (memory not mapped).";
    public const string InvalidMemoryWrite = "Invalid memory write (memory not mapped).";
    public const string InvalidMemorySize = "Invalid memory operation – requested amount is too big or negative.";

}
