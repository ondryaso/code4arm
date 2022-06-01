// LinkingException.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionService.Exceptions;

public class LinkingException : DebuggerException
{
    public LinkingException(string description = ExceptionMessages.Linking)
        : base(ExceptionCodes.LinkId, ExceptionCodes.Link, DebuggerExceptionType.User, description)
    {
    }
}
