// Ungetc.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators.Stdio;

public class Ungetc : IFunctionSimulator
{
    public string Name => "ungetc";

    public void Run(IExecutionEngine engine)
    {
        var c = engine.Engine.RegRead<int>(Arm.Register.R0);
        engine.UngetEmulatedInputChar((char)c);
    }
}
