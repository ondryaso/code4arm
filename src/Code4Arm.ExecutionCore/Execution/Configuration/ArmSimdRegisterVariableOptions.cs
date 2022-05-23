// ArmSimdRegisterVariableOptions.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Debugger;

namespace Code4Arm.ExecutionCore.Execution.Configuration;

public class ArmSimdRegisterVariableOptions
{
    public bool ShowQ { get; init; }
    public DebuggerVariableType[]? QSubtypes { get; init; }

    public bool ShowD { get; init; }
    public DebuggerVariableType[]? DSubtypes { get; init; }
    public bool DIeeeSubvariables { get; init; }

    public bool ShowS { get; init; }
    public DebuggerVariableType[]? SSubtypes { get; init; }
    public bool SIeeeSubvariables { get; init; }

    /// <summary>
    /// If true, D and S registers will be interpreted and rendered as floating point numbers in their corresponding variables.
    /// </summary>
    public bool PreferFloatRendering { get; init; }
}
