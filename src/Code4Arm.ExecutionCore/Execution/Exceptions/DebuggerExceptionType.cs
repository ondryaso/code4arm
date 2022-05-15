// DebuggerExceptionType.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Exceptions;

public enum DebuggerExceptionType
{
    /// <summary>
    /// The error is presented to the user explicitly (e.g. in a pop-up dialog).
    /// In terms of the protocol, this is an ErrorResponse with showUser set to true.
    /// </summary>
    User,
    /// <summary>
    /// The error is logged in the debugger console.
    /// In terms of the protocol, this error triggers an OutputEvent with the 'console' category.
    /// </summary>
    Log,
    /// <summary>
    /// The error is presented as an invalid result of an operation (e.g. evaluating an expression).
    /// In terms of the protocol, this is an ErrorResponse with showUser set to false.
    /// </summary>
    UserImplicit,
    /// <summary>
    /// The error has been caused by using a protocol method in an inappropriate state (e.g. calling a debugger
    /// method when the engine is not running) or with invalid arguments (e.g. a wrong variables reference).
    /// </summary>
    InvalidRequest
}
