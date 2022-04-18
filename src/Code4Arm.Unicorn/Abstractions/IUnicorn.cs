﻿using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Callbacks;

// ReSharper disable InconsistentNaming

namespace Code4Arm.Unicorn.Abstractions;

public interface IUnicorn : IUnicornContext
{
    // uc_version
    (uint Major, uint Minor) Version { get; }

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
    // TODO: what are the possible values for this?
    int CpuModel { get; set; }

    // uc_arch_supported
    bool IsArchSupported(Architecture architecture);

    // uc_query
    ulong Query(QueryType type);

    // uc_ctl, UC_CTL_UC_USE_EXITS, write
    void EnableMultipleExits();

    // Missing: uc_ctl, UC_CTL_TB_REQUEST_CACHE, read 
    // Missing: uc_ctl, UC_CTL_TB_REMOVE_CACHE, write

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

    void AddCodeHook(CodeHookCallback callback, ulong startAddress, ulong endAddress);

    void AddBlockHook(CodeHookCallback callback, ulong startAddress, ulong endAddress);

    void AddInterruptHook(InterruptHookCallback callback, ulong startAddress, ulong endAddress);

    void AddInvalidInstructionHook(InvalidInstructionHookCallback callback, ulong startAddress, ulong endAddress);

    void AddMemoryHook(MemoryHookCallback callback, MemoryHookType hookType, ulong startAddress, ulong endAddress);

    void AddInvalidMemoryAccessHook(InvalidMemoryAccessCallback callback, MemoryHookType hookType, ulong startAddress,
        ulong endAddress);

    void RemoveHook(CodeHookCallback callback);
    void RemoveHook(InterruptHookCallback callback);
    void RemoveHook(InvalidInstructionHookCallback callback);
    void RemoveHook(MemoryHookCallback callback);
    void RemoveHook(InvalidMemoryAccessCallback callback);
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
    void RegBatchWrite<T>(int[] registerIds, IEnumerable<T> values) where T : unmanaged;
    void RegBatchWrite<T>(int[] registerIds, ReadOnlySpan<T> values) where T : unmanaged;
    void RegBatchRead<T>(int[] registerIds, Span<T> target) where T : unmanaged;
    T[] RegBatchRead<T>(int[] registerIds) where T : unmanaged;
}
