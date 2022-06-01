// ExecutionOptions.cs
// Author: Ondřej Ondryáš

using System.Reflection;

namespace Code4Arm.ExecutionCore.Execution.Configuration;

/// <summary>
/// Determines the possible behaviour of virtual stack memory placement and initialization.
/// </summary>
[Flags]
public enum StackPlacementOptions
{
    /// <summary>
    /// The stack will always be placed on the address specified by <see cref="ExecutionOptions.ForcedStackAddress"/>.
    /// Cannot be used together with <see cref="RandomizeAddress"/> or <see cref="AlwaysKeepFirstAddress"/>.
    /// </summary>
    FixedAddress = 1 << 1,

    /// <summary>
    /// The stack will be placed on a random address different for each launch.
    /// </summary>
    RandomizeAddress = 1 << 2,

    /// <summary>
    /// When launching for the first time, the stack address will be generated randomly. On successive launches,
    /// the address will be kept the same (but only when the segments from the executable don't overlap it).
    /// </summary>
    AlwaysKeepFirstAddress = 1 << 3,

    /// <summary>
    /// The stack memory will be cleared (set to zeros) on each launch.
    /// </summary>
    ClearData = 1 << 4,

    /// <summary>
    /// The stack memory will be randomized on each launch.
    /// </summary>
    RandomizeData = 1 << 5,

    /// <summary>
    /// The stack data will always be kept, even if the stack is moved to another location before a successive launch.
    /// </summary>
    KeepData = 1 << 6
}

/// <summary>
/// Determines the possible behaviour of register initialization.
/// </summary>
/// <seealso cref="ExecutionOptions.RegisterInitOptions"/>
/// <seealso cref="ExecutionOptions.SimdRegisterInitOptions"/>
public enum RegisterInitOptions
{
    /// <summary>
    /// Clear registers on each launch.
    /// </summary>
    Clear,

    /// <summary>
    /// Randomize registers on each launch.
    /// </summary>
    Randomize,

    /// <summary>
    /// Clear registers on the first launch and then keep their values.
    /// </summary>
    Keep,

    /// <summary>
    /// Randomize registers on the first launch and then keep their values.
    /// </summary>
    RandomizeFirst
}

/// <summary>
/// Determines the possible types of stack pointer usage.
/// </summary>
/// <seealso cref="ExecutionOptions.StackPlacementOptions"/>
public enum StackPointerType
{
    /// <summary>
    /// SP points to a place in the stack memory where the last word is stored (hence full).
    /// When pushing onto the stack, the address is decremented – the stack is filled from the end of its memory space
    /// to its beginning.
    /// The initial SP value is a word-aligned address right after the last word-aligned address in the stack space.
    /// </summary>
    FullDescending,

    /// <summary>
    /// SP points to a place in the stack memory where the last word is stored (hence full).
    /// When pushing onto the stack, the address is incremented – the stack is filled from the beginning of its memory space
    /// to its end.
    /// The initial SP value is a word-aligned address right before the first word-aligned address in the stack space.
    /// </summary>
    FullAscending,

    /// <summary>
    /// SP points to a place in the stack memory where the next word will be stored (hence empty).
    /// When pushing onto the stack, the address is decremented – the stack is filled from the end of its memory space
    /// to its beginning.
    /// The initial SP value is the last word-aligned address in the stack space.
    /// </summary>
    EmptyDescending,

    /// <summary>
    /// SP points to a place in the stack memory where the next word will be stored (hence empty).
    /// When pushing onto the stack, the address is incremented – the stack is filled from the beginning of its memory space
    /// to its end.
    /// The initial SP value is the first word-aligned address in the stack space.
    /// </summary>
    EmptyAscending
}

/// <summary>
/// Determines the possible Step Back behaviours.
/// </summary>
public enum StepBackMode
{
    /// <summary>
    /// Step Back is disabled.
    /// </summary>
    None,

    /// <summary>
    /// The CPU state is saved every time a Step is performed.
    /// The states are kept on a stack for consecutive steps.
    /// Step Back may only be invoked to the point before the first step. 
    /// When executing Continue, the stacked CPU states are cleared.
    /// </summary>
    CaptureOnStep
}

public class ExecutionOptions
{
    /// <summary>
    /// The timeout used when invoking Unicorn emulation. The default is 5 seconds.
    /// </summary>
    public int Timeout { get; set; } = 10000;

    /// <summary>
    /// The size of emulation stack memory. The default is 2 MiB. 
    /// </summary>
    [OptionChangeBehavior(OptionChangeBehavior.ReloadExecutable)]
    public uint StackSize { get; set; } = 2 * 1024 * 1024;

    /// <summary>
    /// Sets a specific stack address that will be used every time an executable is loaded.
    /// Only used when <see cref="StackPlacementOptions"/> contains the <see cref="Configuration.StackPlacementOptions.FixedAddress"/> flag.
    /// </summary>
    [OptionChangeBehavior(OptionChangeBehavior.ReloadExecutable)]
    public uint ForcedStackAddress { get; set; } = 0x40000000;

    /// <summary>
    /// Controls whether the emulated stack should be pre-filled with random data.
    /// </summary>
    [OptionChangeBehavior(OptionChangeBehavior.ReloadExecutable)]
    public StackPlacementOptions StackPlacementOptions { get; set; } =
        StackPlacementOptions.RandomizeAddress;

    /// <summary>
    /// Controls the initial position of the stack pointer after loading an executable.
    /// This should be always set to <see cref="Configuration.StackPointerType.FullDescending"/> because that's the
    /// behaviour required by Armv8. With other configurations, some debugger features may not work.
    /// </summary>
    [OptionChangeBehavior(OptionChangeBehavior.ReloadExecutable)]
    public StackPointerType StackPointerType { get; set; } = StackPointerType.FullDescending;

    /// <summary>
    /// Controls whether space around memory segments defined by the executable should be filled with random data.
    /// </summary>
    /// <remarks>
    /// When allocating an emulation memory segment, its start address and size has to be aligned on a 4096B boundary.
    /// This means that often there's more accessible memory around these segments. This option allows filling it
    /// with random data.
    /// </remarks>
    public bool RandomizeExtraAllocatedSpaceContents { get; set; } = true;

    /// <summary>
    /// Controls whether space around memory segments defined by the executable should be inaccessible.
    /// </summary>
    /// <remarks>
    /// When allocating an emulation memory segment, its start address and size has to be aligned on a 4096B boundary.
    /// This means that often there's more accessible memory around these segments. Setting this option to true will
    /// cause execution to halt when these are accessed (anyhow), as if they were unmapped memory.
    /// </remarks>
    [OptionChangeBehavior(OptionChangeBehavior.RecreateEngine)]
    public bool UseStrictMemoryAccess { get; set; } = true;

    /// <summary>
    /// If true, the executable will be instrumented on each instruction.
    /// Runtime exceptions will carry correct program counter/line information.
    /// Data Breakpoints will be available for register values.
    /// </summary>
    /// <remarks>
    /// This is necessary because Unicorn doesn't trace the PC accurately when there's no code hook registered
    /// in the address range – so if an exception occurs, the PC reading is incorrect. Registering a code hook
    /// together with the memory hooks prevents this but it affects performance (quite terribly, see Unicorn FAQ, issue
    /// #534 and referencing issues). When enabled, the code hook is also used to trace register values between
    /// instruction executions (this is not possible without reading and comparing the traced register value after
    /// each instruction).
    /// </remarks>
    [OptionChangeBehavior(OptionChangeBehavior.ReloadExecutable)]
    public bool EnableAccurateExecutionTracking { get; set; } = true;

    /// <summary>
    /// Controls the initial values of general-purpose registers (R0 to R13/LR).
    /// </summary>
    public RegisterInitOptions RegisterInitOptions { get; set; } = RegisterInitOptions.Randomize;

    /// <summary>
    /// Controls the initial values of all the SIMD/FP registers.
    /// When filling with random values, the 64b Dx registers are used as the target, the random values being valid
    /// double precision floating point numbers between -1024.0 and 1024.0. 
    /// </summary>
    public RegisterInitOptions SimdRegisterInitOptions { get; set; } = RegisterInitOptions.Randomize;

    /// <summary>
    /// Controls the Step Back mode.
    /// </summary>
    [OptionChangeBehavior(OptionChangeBehavior.RecreateEngine)]
    public StepBackMode StepBackMode { get; set; } = StepBackMode.CaptureOnStep;

    public OptionChangeBehavior Compare(ExecutionOptions other)
    {
        var type = typeof(ExecutionOptions);
        var properties = type.GetProperties();
        var ret = OptionChangeBehavior.None;

        foreach (var property in properties)
        {
            var behaviourAttribute = property.GetCustomAttribute<OptionChangeBehaviorAttribute>();

            if (behaviourAttribute is null or { Behavior: OptionChangeBehavior.None })
                continue;

            var thisValue = property.GetValue(this);
            var otherValue = property.GetValue(other);

            if (!(thisValue?.Equals(otherValue) ?? false))
            {
                // RecreateEngine implies ReloadExecutable; when one property triggers recreating executable,
                // we can just return that and not check the rest of the properties
                if (behaviourAttribute.Behavior == OptionChangeBehavior.RecreateEngine)
                    return OptionChangeBehavior.RecreateEngine;

                ret = OptionChangeBehavior.ReloadExecutable;
            }
        }

        return ret;
    }
}
