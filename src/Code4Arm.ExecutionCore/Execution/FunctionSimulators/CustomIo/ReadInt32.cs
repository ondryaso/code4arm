// ReadInt32.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators.CustomIo;

public class ReadInt32 : IFunctionSimulator
{
    public string Name => "ReadInt32";
    public void Run(IExecutionEngine engine)
    {
        var input = engine.WaitForEmulatedInputLine();
        if (int.TryParse(input, out var i))
        {
            engine.Engine.RegWrite(Arm.Register.R0, i);
        }
        else
        {
            engine.Engine.RegWrite(Arm.Register.R0, int.MinValue);
        }
    }
}
