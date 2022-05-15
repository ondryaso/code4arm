// ConfigurationException.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public class ConfigurationException : DebuggerException
{
    public ConfigurationException(string description,
        Exception? innerException = null) : base(ExceptionCodes.ConfigurationId, ExceptionCodes.Configuration,
        DebuggerExceptionType.InvalidRequest, description, innerException)
    {
    }
}
