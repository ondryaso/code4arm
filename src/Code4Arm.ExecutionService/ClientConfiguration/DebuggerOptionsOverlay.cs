// DebuggerOptionsOverlay.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Debugger;

namespace Code4Arm.ExecutionService.ClientConfiguration;

/// <summary>
/// A configuration overlay for <see cref="DebuggerOptions"/>.
/// For property reference, see its documentation.
/// </summary>
public class DebuggerOptionsOverlay
{
    public bool? EnableAutomaticDataVariables { get; set; }
    public bool? EnableStackVariables { get; set; }
    public bool? EnableRegistersVariables { get; set; }
    public bool? EnableSimdVariables { get; set; }
    public bool? EnableControlVariables { get; set; }
    public bool? EnableExtendedControlVariables { get; set; }
    public VariableNumberFormat? VariableNumberFormat { get; set; }
    public DebuggerVariableType[]? RegistersSubtypes { get; set; }
    public DebuggerVariableType[]? StackVariablesSubtypes { get; set; }
    public bool? ShowFloatIeeeSubvariables { get; set; }
    public SimdRegisterLevel? TopSimdRegistersLevel { get; set; }
    public ArmSimdRegisterVariableOptionsOverlay? SimdRegistersOptions { get; set; }
    public int? CStringMaxLength { get; set; }
    public string? CStringEncoding { get; set; }
}
