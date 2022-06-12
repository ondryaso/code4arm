// Puts.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.Unicorn.Abstractions.Extensions;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators.Stdio;

public class Puts : IFunctionSimulator
{
    public string Name => "puts";

    public void Run(IExecutionEngine engine)
    {
        var ptr = engine.Engine.RegRead<uint>(Arm.Register.R0);
        var str = engine.Engine.MemReadCString(ptr, engine.DebugProvider.Options.CStringMaxLength,
            encoding: engine.DebugProvider.Options.CStringEncoding);
        engine.EmulatedOutput.Write(str);
    }
}
