// ExecutionOptionsOverlay.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Configuration;

namespace Code4Arm.ExecutionService.ClientConfiguration;

public class ExecutionOptionsOverlay
{
    public int? Timeout { get; set; }
    public uint? StackSize { get; set; }
    public uint? ForcedStackAddress { get; set; }
    public StackPlacementOptions[]? StackPlacementOptions { get; set; }
    public StackPointerType? StackPointerType { get; set; }
    public bool? RandomizeExtraAllocatedSpaceContents { get; set; }
    public bool? UseStrictMemoryAccess { get; set; }
    public bool? EnableAccurateExecutionTracking { get; set; }
    public RegisterInitOptions? RegisterInitOptions { get; set; }
    public RegisterInitOptions? SimdRegisterInitOptions { get; set; }
    public StepBackMode? StepBackMode { get; set; }
}
