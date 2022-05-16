// Printf.cs
// Author: Ondřej Ondryáš

using System.Text;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Extensions;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators;

public class Printf : IFunctionSimulator
{
    public string Name => "printf";

    public void Run(IExecutionEngine engine)
    {
        var address = engine.Engine.RegRead<uint>(Arm.Register.R0);
        var formatString = engine.Engine.MemReadCString(address);

        // TODO
        engine.EmulatedOutput.Write(formatString);
    }
}
