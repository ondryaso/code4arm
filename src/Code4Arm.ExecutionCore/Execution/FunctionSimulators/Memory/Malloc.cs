// Malloc.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.ExecutionStateFeatures;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators.Memory;

public class Malloc : IFunctionSimulator
{
    public string Name => "malloc";

    public void Run(IExecutionEngine engine)
    {
        var heapFeature = engine.GetStateFeature<HeapFeature>();
        var targetSize = engine.Engine.RegRead<uint>(Arm.Register.R0);
        var allocated = heapFeature!.Allocate(targetSize, false)
            ?? 0;
        engine.Engine.RegWrite(Arm.Register.R0, allocated);
    }
}
