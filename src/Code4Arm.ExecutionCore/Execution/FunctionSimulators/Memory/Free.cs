// Malloc.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.ExecutionStateFeatures;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators.Memory;

public class Free : IFunctionSimulator
{
    public string Name => "free";

    public void Run(IExecutionEngine engine)
    {
        var heapFeature = engine.GetStateFeature<HeapFeature>();
        var targetPtr = engine.Engine.RegRead<uint>(Arm.Register.R0);
        heapFeature!.Free(targetPtr);
    }
}
