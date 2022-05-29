// ExceptionCodes.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionService;

public static class ExceptionCodes
{
    public const int UnexpectedErrorId = ExecutionCore.Execution.Exceptions.ExceptionCodes.UnexpectedErrorId;
    public const string UnexpectedError = ExecutionCore.Execution.Exceptions.ExceptionCodes.UnexpectedError;
    
    public const int NoLaunchTargetId = 200;
    public const string NoLaunchTarget = "noTarget";
    
    public const int AssembleId = 201;
    public const string Assemble = "assemble";
    
    public const int LinkId = 202;
    public const string Link = "link";
}
