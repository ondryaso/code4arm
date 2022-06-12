// Putchar.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators.Stdio;

public class Putchar : IFunctionSimulator
{
    public string Name => "putchar";

    public void Run(IExecutionEngine engine)
    {
        var c = (char)engine.Engine.RegRead<int>(Arm.Register.R0);
        engine.EmulatedOutput.Write(c);
    }
}
