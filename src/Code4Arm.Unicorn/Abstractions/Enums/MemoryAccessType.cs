namespace Code4Arm.Unicorn.Abstractions.Enums;

// Original: uc_mem_type
public enum MemoryAccessType
{
    Read = 16, // Memory is read from
    Write, // Memory is written to
    Fetch, // Memory is fetched
    ReadUnmapped, // Unmapped memory is read from
    WriteUnmapped, // Unmapped memory is written to
    FetchUnmapped, // Unmapped memory is fetched
    WriteProtected, // Write to write protected, but mapped, memory
    ReadProtected, // Read from read protected, but mapped, memory
    FetchProtected, // Fetch from non-executable, but mapped, memory
    AfterRead, // Memory is read from (successful access)
}