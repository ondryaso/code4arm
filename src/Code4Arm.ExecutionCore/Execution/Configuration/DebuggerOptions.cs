// DebuggerOptions.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Debugger;

namespace Code4Arm.ExecutionCore.Execution.Configuration;

public enum VariableNumberFormat
{
    Decimal,
    Hex,
    Binary
}

public enum SimdRegisterLevel
{
    S32,
    D64,
    Q128
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
    public bool EnableExtendedControlVariables { get; set; } = true;

    /// <summary>
    /// Number format to show variable values in.
    /// </summary>
    public VariableNumberFormat VariableNumberFormat { get; set; } = VariableNumberFormat.Hex;

    /// <summary>
    /// Different subtypes to break general-purpose register values into. 
    /// </summary>
    /// <remarks>
    /// <see cref="DebuggerVariableType.LongS"/>, <see cref="DebuggerVariableType.LongU"/> and <see cref="DebuggerVariableType.Double"/> cannot be used here
    /// because the registers are 32 bits wide.
    /// </remarks>
    public DebuggerVariableType[] RegistersSubtypes { get; set; } =
    {
        DebuggerVariableType.ByteU, DebuggerVariableType.ByteS, /*DebuggerVariableType.CharAscii, DebuggerVariableType.ShortU,
        DebuggerVariableType.ShortS,*/ DebuggerVariableType.IntU, DebuggerVariableType.IntS, DebuggerVariableType.Float
    };

    /// <summary>
    /// Different subtypes to break stack values into. 
    /// </summary>
    /// <remarks>
    /// <see cref="DebuggerVariableType.LongS"/>, <see cref="DebuggerVariableType.LongU"/> and <see cref="DebuggerVariableType.Double"/> cannot be used here
    /// because the stack is read as an array of 32bit values.
    /// </remarks>
    public DebuggerVariableType[] StackVariablesSubtypes { get; set; } =
    {
        DebuggerVariableType.ByteU, /*DebuggerVariableType.ByteS, DebuggerVariableType.CharAscii, DebuggerVariableType.ShortU,
        DebuggerVariableType.ShortS,*/ DebuggerVariableType.IntU, DebuggerVariableType.IntS, DebuggerVariableType.Float
    };

    /// <summary>
    /// Controls which class of SIMD register is returned in the top-level 'SIMD/FP' variables scope.
    /// </summary>
    public SimdRegisterLevel TopSimdRegistersLevel { get; set; } = SimdRegisterLevel.Q128;

    /// <summary>
    /// If true, D and S registers will be interpreted as floating point numbers in their corresponding variables.
    /// </summary>
    public bool ShowSimdRegistersAsFp { get; set; } = true;
}
