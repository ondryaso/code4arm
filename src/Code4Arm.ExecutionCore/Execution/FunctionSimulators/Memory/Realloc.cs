// Malloc.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.ExecutionStateFeatures;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators.Memory;

public class Realloc : IFunctionSimulator
{
    public string Name => "realloc";

    public void Run(IExecutionEngine engine)
    {
        var heapFeature = engine.GetStateFeature<HeapFeature>();
        var targetPtr = engine.Engine.RegRead<uint>(Arm.Register.R0);
        var targetSize = engine.Engine.RegRead<uint>(Arm.Register.R1);
        var allocated = heapFeature!.Reallocate(targetPtr, targetSize)
            ?? 0;
        engine.Engine.RegWrite(Arm.Register.R0, allocated);
    }
}
