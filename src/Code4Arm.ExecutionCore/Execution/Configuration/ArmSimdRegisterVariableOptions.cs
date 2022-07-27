// ArmSimdRegisterVariableOptions.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Debugger;

namespace Code4Arm.ExecutionCore.Execution.Configuration;

public record ArmSimdRegisterVariableOptions
{
    /// <summary>
    /// Different subtypes to break the D registers' values into. 
    /// </summary>
    /// <remarks>
    /// Currently, only <see cref="DebuggerVariableType.Float"/>, <see cref="DebuggerVariableType.IntU"/>,
    /// <see cref="DebuggerVariableType.LongU"/> and <see cref="DebuggerVariableType.Double"/>
    /// are supported.
    /// </remarks>
    public DebuggerVariableType[]? QSubtypes { get; init; }

    /// <summary>
    /// Show D registers.
    /// </summary>
    public bool ShowD { get; init; }
        
    /// <summary>
    /// Different subtypes to break the D registers' values into. 
    /// </summary>
    public DebuggerVariableType[]? DSubtypes { get; init; }
    
    /// <summary>
    /// Show IEEE 754 decomposition variables for the 64b values in the D registers.
    /// </summary>
    public bool DIeeeSubvariables { get; init; }

    /// <summary>
    /// Show S registers.
    /// </summary>
    public bool ShowS { get; init; }
    
    /// <summary>
    /// Different subtypes to break the S registers' values into. 
    /// </summary>
    /// <remarks>
    /// <see cref="DebuggerVariableType.LongS"/>, <see cref="DebuggerVariableType.LongU"/> and <see cref="DebuggerVariableType.Double"/> cannot be used here
    /// because the registers are 32 bits wide.
    /// </remarks>
    public DebuggerVariableType[]? SSubtypes { get; init; }
    
    /// <summary>
    /// Show IEEE 754 decomposition variables for the 32b values in the S registers.
    /// </summary>
    public bool SIeeeSubvariables { get; init; }

    /// <summary>
    /// If true, D and S registers will be interpreted and rendered as floating point numbers in their corresponding variables.
    /// </summary>
    public bool PreferFloatRendering { get; init; }
}
