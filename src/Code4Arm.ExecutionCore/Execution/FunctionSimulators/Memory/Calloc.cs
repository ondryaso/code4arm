// Malloc.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.ExecutionStateFeatures;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators.Memory;

public class Calloc : IFunctionSimulator
{
    public string Name => "calloc";

    public void Run(IExecutionEngine engine)
    {
        var heapFeature = engine.GetStateFeature<HeapFeature>();
        var targetNum = engine.Engine.RegRead<uint>(Arm.Register.R0);
        var targetSize = engine.Engine.RegRead<uint>(Arm.Register.R1);
        var allocated = heapFeature!.Allocate(targetSize * targetNum, true)
            ?? 0;
        
        engine.Engine.RegWrite(Arm.Register.R0, allocated);
    }
}
