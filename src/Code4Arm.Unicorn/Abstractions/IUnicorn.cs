using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Callbacks;

// ReSharper disable InconsistentNaming

namespace Code4Arm.Unicorn.Abstractions;

public interface IUnicorn : IUnicornContext
{
    // uc_version
    (uint Major, uint Minor) Version { get; }

    /// <summary>
    /// Checks whether the used Unicorn library version matches the one this binding was built for.
    /// </summary>
    /// <param name="throwIfNot">If true, this method will throw an <see cref="UnicornException"/> on mismatch.</param>
    /// <param name="considerMinor">If true, different 'minor' version numbers will be considered mismatching.</param>
    /// <returns>True if Unicorn is the same version this binding was build for.</returns>
    bool CheckIfBindingMatchesLibrary(bool throwIfNot = false, bool considerMinor = true);

    // uc_ctl, UC_CTL_UC_MODE, read
    int CurrentMode { get; }

    // uc_ctl, UC_CTL_UC_PAGE_SIZE, read/write
    uint CurrentPageSize { get; set; }

    // uc_ctl, UC_CTL_UC_ARCH, read
    int CurrentArch { get; }

    // uc_ctl, UC_CTL_UC_TIMEOUT, read
    ulong CurrentTimeout { get; }

    // uc_ctl, UC_CTL_UC_EXITS_CNT, read
    nuint CurrentNumberOfExits { get; }

    // uc_ctl, UC_CTL_UC_EXITS, read/write
    ulong[] Exits { get; set; }

    // uc_ctl, UC_CTL_CPU_MODEL, read/write
    int CpuModel { get; set; }
    
    // uc_arch_supported
    bool IsArchSupported(Architecture architecture);

    // uc_query
    ulong Query(QueryType type);

    // uc_ctl, UC_CTL_UC_USE_EXITS, write
    void EnableMultipleExits();

    // Missing: uc_ctl, UC_CTL_TB_REQUEST_CACHE, read 
    
    // uc_ctl, UC_CTL_TB_REMOVE_CACHE, write
    void RemoveTbCache(ulong begin, ulong end);

    void GetExits(Span<ulong> target);
    void SetExits(ReadOnlySpan<ulong> exits);
    void SetExits(ReadOnlySpan<ulong> exits, int length);

    void MemWrite(ulong address, byte[] bytes);
    void MemWrite(ulong address, byte[] bytes, nuint size);
    void MemWrite(ulong address, ReadOnlySpan<byte> bytes);
    void MemWrite(ulong address, ReadOnlySpan<byte> bytes, nuint size);

    byte[] MemRead(ulong address, nuint size);
    void MemRead(ulong address, byte[] target);
    void MemRead(ulong address, byte[] target, nuint size);
    void MemRead(ulong address, Span<byte> target);
    void MemRead(ulong address, Span<byte> target, nuint size);

    void EmuStart(ulong start, ulong until, ulong timeout = 0, ulong count = 0);

    void EmuStop();

    nuint AddNativeHook(IntPtr callbackPointer, int type, ulong startAddress, ulong endAddress, nint userData = 0);
    nuint AddNativeHook(Delegate callback, int type, ulong startAddress, ulong endAddress, nint userData = 0);

    UnicornHookRegistration AddCodeHook(CodeHookCallback callback, ulong startAddress, ulong endAddress);

    UnicornHookRegistration AddBlockHook(CodeHookCallback callback, ulong startAddress, ulong endAddress);

    UnicornHookRegistration AddInterruptHook(InterruptHookCallback callback);

    UnicornHookRegistration AddInvalidInstructionHook(InvalidInstructionHookCallback callback);

    UnicornHookRegistration AddMemoryHook(MemoryHookCallback callback, MemoryHookType hookType, ulong startAddress,
        ulong endAddress);

    UnicornHookRegistration AddInvalidMemoryAccessHook(InvalidMemoryAccessCallback callback, MemoryHookType hookType,
        ulong startAddress,
        ulong endAddress);

    void RemoveHook(UnicornHookRegistration registration);
    void RemoveNativeHook(nuint hookId);

    void MemMap(ulong address, nuint size, MemoryPermissions permissions);
    void MemMap(ulong address, nuint size, MemoryPermissions permissions, IntPtr memoryPointer);
    void MemMap(ulong address, nuint size, MMIOReadCallback? readCallback, MMIOWriteCallback? writeCallback);

    void MemUnmap(ulong address, nuint size);

    IUnicornContext MakeEmptyContext();
    IUnicornContext SaveContext();
    void SaveContext(IUnicornContext context);
    void RestoreContext(IUnicornContext context);
}

public interface IUnicornContext : IDisposable
{
    void RegWrite<T>(int registerId, T value) where T : unmanaged;
    T RegRead<T>(int registerId) where T : unmanaged;
    void RegRead<T>(int registerId, ref T target) where T : unmanaged;
    void RegWrite(int registerId, ReadOnlySpan<byte> bytes);
    void RegRead(int registerId, Span<byte> target);
    void RegBatchWrite<T>(ReadOnlySpan<int> registerIds, IEnumerable<T> values) where T : unmanaged;
    void RegBatchWrite<T>(ReadOnlySpan<int> registerIds, ReadOnlySpan<T> values) where T : unmanaged;
    void RegBatchRead<T>(ReadOnlySpan<int> registerIds, Span<T> target) where T : unmanaged;
    T[] RegBatchRead<T>(ReadOnlySpan<int> registerIds) where T : unmanaged;
}
