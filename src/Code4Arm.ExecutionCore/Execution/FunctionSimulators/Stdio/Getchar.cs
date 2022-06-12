// Getchar.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators.Stdio;

public class Getchar : IFunctionSimulator
{
    public string Name => "getchar";

    public void Run(IExecutionEngine engine)
    {
        var input = engine.WaitForEmulatedInput(1);
        var firstChar = (int) input[0];
        engine.Engine.RegWrite(Arm.Register.R0, firstChar);
    }
}
