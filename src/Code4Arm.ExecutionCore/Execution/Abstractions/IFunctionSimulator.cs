// IFunctionSimulator.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

/// <summary>
/// Represents a simulated function, identified by a name.
/// </summary>
public interface IFunctionSimulator
{
    /// <summary>
    /// The name of the function symbol.
    /// </summary>
    string Name { get; }
    
    /// <summary>
    /// The handling method executed when the simulated function is called in the emulated code.
    /// </summary>
    /// <param name="engine">The <see cref="IExecutionEngine"/> executing the calling code.</param>
    void Run(IExecutionEngine engine);
}
