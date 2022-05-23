// DebuggerOptions.cs
// Author: Ondřej Ondryáš

using System.Text;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Debugger;

namespace Code4Arm.ExecutionCore.Execution.Configuration;

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
        DebuggerVariableType.ByteU,
        DebuggerVariableType.ByteS, /*DebuggerVariableType.CharAscii, DebuggerVariableType.ShortU,
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
        DebuggerVariableType
            .ByteU, /*DebuggerVariableType.ByteS, DebuggerVariableType.CharAscii, DebuggerVariableType.ShortU,
        DebuggerVariableType.ShortS,*/ DebuggerVariableType.IntU, DebuggerVariableType.IntS, DebuggerVariableType.Float
    };

    /// <summary>
    /// If true, all variables, including subvariables, that carry a float or double value, will have child variables
    /// with details of how the number is stored in the IEEE 754 format. 
    /// </summary>
    public bool ShowFloatIeeeSubvariables { get; set; } = true;

    /// <summary>
    /// Controls which class of SIMD register is returned in the top-level 'SIMD/FP' variables scope.
    /// </summary>
    public SimdRegisterLevel TopSimdRegistersLevel { get; set; } = SimdRegisterLevel.Q128;

    /// <summary>
    /// 
    /// </summary>
    public ArmSimdRegisterVariableOptions SimdRegistersOptions { get; set; } = new()
    {
        ShowQ = true,
        ShowD = true,
        ShowS = true,

        DIeeeSubvariables = true,
        SIeeeSubvariables = true,

        PreferFloatRendering = true,

        QSubtypes = new[] { DebuggerVariableType.LongU, DebuggerVariableType.IntU },
        DSubtypes = new[] { DebuggerVariableType.IntU, DebuggerVariableType.Float, DebuggerVariableType.Double },
        SSubtypes = new[] { DebuggerVariableType.IntU, DebuggerVariableType.Float, DebuggerVariableType.ByteS }
    };

    /// <summary>
    /// Controls the maximum number of bytes the debugger will read from memory when reading a null-terminated C-string
    /// before giving up.
    /// </summary>
    public int CStringMaxLength { get; set; } = 512;

    /// <summary>
    /// Controls the encoding used to convert read bytes to string and vice-versa when dealing with null-terminated
    /// C-strings.
    /// </summary>
    public Encoding CStringEncoding { get; set; } = Encoding.UTF8;
}
