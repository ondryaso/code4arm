// ExecutionOptions.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Configuration;

[Flags]
public enum StackPlacementOptions
{
    FixedAddress = 1 << 1,
    RandomizeAddress = 1 << 2,
    AlwaysKeepFirstAddress = 1 << 3,
    ClearData = 1 << 4,
    RandomizeData = 1 << 5,
    KeepData = 1 << 6
}

public enum RegisterInitOptions
{
    Clear,
    Randomize,
    Keep,
    ClearFirst,
    RandomizeFirst
}

public enum StackPointerType
{
    FullDescending,
    FullAscending,
    EmptyDescending,
    EmptyAscending
}

public enum StepBackMode
{
    None,
    CaptureOnBreakpoint
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
    public uint StackSize { get; set; } = 2 * 1024 * 1024;


    /// <summary>
    /// Sets a specific stack address that will be used every time an executable is loaded.
    /// Only used when <see cref="StackPlacementOptions"/> contains the <see cref="Configuration.StackPlacementOptions.FixedAddress"/> flag.
    /// </summary>
    public uint ForcedStackAddress { get; set; } = 0;

    /// <summary>
    /// Controls whether the emulated stack should be pre-filled with random data.
    /// </summary>
    public StackPlacementOptions StackPlacementOptions { get; set; } =
        StackPlacementOptions.RandomizeData | StackPlacementOptions.RandomizeAddress;

    /// <summary>
    /// Controls the initial position of the stack pointer after loading an executable. 
    /// </summary>
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
    public bool UseStrictMemoryAccess { get; set; } = true;
    
    /// <summary>
    /// If true, runtime exceptions will carry correct program counter/line information.
    /// </summary>
    /// <remarks>
    /// This is necessary because Unicorn doesn't trace the PC accurately when there's no code hook registered
    /// in the address range – so if an exception occurs, the PC reading is incorrect. Registering a dummy code hook
    /// together with the memory hooks prevents this but it affects performance (quite terribly, see Unicorn issue
    /// #534 and referencing issues).
    /// </remarks>
    public bool EnableAccurateExceptionInfo { get; set; } = true;

    public RegisterInitOptions RegisterInitOptions { get; set; } = RegisterInitOptions.Clear;

    /// <summary>
    /// Controls the Step Back mode.
    /// </summary>
    public StepBackMode StepBackMode { get; set; } = StepBackMode.CaptureOnBreakpoint;
    
    // TODO
    public bool EnableRegisterDataBreakpoints { get; set; }
}
