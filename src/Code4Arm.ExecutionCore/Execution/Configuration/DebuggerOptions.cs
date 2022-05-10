// DebuggerOptions.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;

namespace Code4Arm.ExecutionCore.Execution.Configuration;

public enum VariableNumberFormat
{
    Decimal,
    Hex,
    Binary
}

public class DebuggerOptions
{
    /// <summary>
    /// If true, symbols from the data section will be returned in a top-level variables scope.
    /// <see cref="IDebugProvider.MakeVariableScopes"/>.
    /// </summary>
    public bool EnableAutomaticDataVariables { get; set; } = true;

    /// <summary>
    /// If true, stack will be represented as a collection of variables in a top-level variables scope.
    /// </summary>
    public bool EnableStackVariables { get; set; } = true;

    /// <summary>
    /// If true, general-purpose registers will be represented as a collection of variables in a top-level variables scope.
    /// </summary> 
    public bool EnableRegistersVariables { get; set; } = true;

    /// <summary>
    /// If true, SIMD/FP registers will be represented as a collection of variables in a top-level variables scope.
    /// </summary>
    public bool EnableSimdVariables { get; set; } = true;
    
    /// <summary>
    /// If true, basic control registers will be represented as a collection of variables in a top-level variables scope.
    /// </summary> 
    public bool EnableControlVariables { get; set; } = true;
    
    /// <summary>
    /// If true, more control registers will be included in the control registers variables scope.
    /// </summary> 
    public bool EnableExtendedControlVariables { get; set; } = false;

    public VariableNumberFormat VariableNumberFormat { get; set; } = VariableNumberFormat.Hex;
}
