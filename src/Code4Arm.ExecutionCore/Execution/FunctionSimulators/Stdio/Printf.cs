// Printf.cs
// Author: Ondřej Ondryáš

using AT.MIN;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.Unicorn.Abstractions.Extensions;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators.Stdio;

public class Printf : IFunctionSimulator
{
    public string Name => "printf";

    public void Run(IExecutionEngine engine)
    {
        var r0 = engine.Engine.RegRead<uint>(Arm.Register.R0);
        var formatString = engine.Engine.MemReadCString(r0, engine.DebugProvider.Options.CStringMaxLength,
            encoding: engine.DebugProvider.Options.CStringEncoding);
        var result = Tools.PrintF(formatString, engine.Engine);
        engine.EmulatedOutput.Write(result);
    }
}
