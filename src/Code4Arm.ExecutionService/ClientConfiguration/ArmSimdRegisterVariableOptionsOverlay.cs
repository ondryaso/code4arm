// ArmSimdRegisterVariableOptionsOverlay.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Debugger;

namespace Code4Arm.ExecutionService.ClientConfiguration;

public class ArmSimdRegisterVariableOptionsOverlay
{
    public DebuggerVariableType[]? QSubtypes { get; set; }
    public bool? ShowD { get; set; }
    public DebuggerVariableType[]? DSubtypes { get; set; }
    public bool? DIeeeSubvariables { get; set; }
    public bool? ShowS { get; set; }
    public DebuggerVariableType[]? SSubtypes { get; set; }
    public bool? SIeeeSubvariables { get; set; }
    public bool? PreferFloatRendering { get; set; }
}
