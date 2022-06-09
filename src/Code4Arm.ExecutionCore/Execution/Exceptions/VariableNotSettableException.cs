// VariableNotSettableException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class VariableNotSettableException : DebuggerException
{
    public VariableNotSettableException(string description = ExceptionMessages.VariableNotSettable,
        Exception? innerException = null) : base(ExceptionCodes.VariableNotSettableId, ExceptionCodes.VariableNotSettable,
        DebuggerExceptionType.InvalidRequest, description, innerException)
    {
    }
}
