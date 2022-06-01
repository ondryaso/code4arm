// AssemblingException.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionService.Exceptions;

public class AssemblingException : DebuggerException
{
    public AssemblingException(string description)
        : base(ExceptionCodes.AssembleId, ExceptionCodes.Assemble, DebuggerExceptionType.User, description)
    {
    }
}
