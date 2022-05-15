namespace Code4Arm.Unicorn.Abstractions.Enums;

[Flags]
public enum MemoryHookType
{
    ReadUnmapped = 1 << 4,

    // Hook for invalid memory write events
    WriteUnmapped = 1 << 5,

    // Hook for invalid memory fetch for execution events
    FetchUnmapped = 1 << 6,

    // Hook for memory read on read-protected memory
    ReadProtected = 1 << 7,

    // Hook for memory write on write-protected memory
    WriteProtected = 1 << 8,

    // Hook for memory fetch on non-executable memory
    FetchProtected = 1 << 9,

    // Hook memory read events.
    Read = 1 << 10,

    // Hook memory write events.
    Write = 1 << 11,

    // Hook memory fetch for execution events
    Fetch = 1 << 12,

    // Hook memory read events, but only successful access.
    // The callback will be triggered after successful read.
    AfterRead = 1 << 13,

    AllUnmappedEvents = ReadUnmapped | WriteUnmapped | FetchUnmapped,
    AllProtectedEvents = ReadProtected | WriteProtected | FetchProtected,
    AllInvalidEvents = AllUnmappedEvents | AllProtectedEvents,
    AllValidAccessEvents = Read | Write | Fetch,
    AllPreEvents = AllUnmappedEvents | AllProtectedEvents | AllInvalidEvents | AllValidAccessEvents,
    All = AllPreEvents | AfterRead
}
