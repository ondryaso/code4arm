using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Constants;
using Architecture = Code4Arm.Unicorn.Abstractions.Enums.Architecture;

// ReSharper disable InconsistentNaming

namespace Code4Arm.Unicorn;

public class Unicorn : IUnicorn
{
    private bool _disposed;
    private UIntPtr _engine;

    private readonly Dictionary<Delegate, nuint> _hookIdsForDelegates = new();
    private readonly List<Delegate> _managedHooks = new();
    private readonly Dictionary<Delegate, IntPtr> _nativeHooks = new(8);
    private readonly List<UnicornContext> _contexts = new();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int MakeReadControlType(int numberOfArgs, int controlType)
        => controlType | (numberOfArgs << 26) | (2 << 30);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int MakeWriteControlType(int numberOfArgs, int controlType)
        => controlType | (numberOfArgs << 26) | (1 << 30);

    public unsafe Unicorn(Architecture architecture, EngineMode mode)
    {
        var ptr = new UIntPtr();
        var result = Native.uc_open((int) architecture, (int) mode, &ptr);
        this.CheckResult(result);
        _engine = ptr;
    }

    #region Helpers

    internal void CheckResult(int result)
    {
        if (result == UniConst.Err.Ok) return;
        var resultMessagePtr = Native.uc_strerror(result);
        var resultMessage = Marshal.PtrToStringAnsi(resultMessagePtr);
        throw new UnicornException(result, $"[{result}] {resultMessage}");
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal void EnsureEngine()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(Unicorn));
    }

    #endregion

    #region Engine info

    private (uint, uint)? _version;

    public unsafe (uint Major, uint Minor) Version
    {
        get
        {
            if (_version.HasValue)
                return _version.Value;

            uint major = 0, minor = 0;
#pragma warning disable CA1806
            Native.uc_version(&major, &minor);
#pragma warning restore CA1806
            _version = (major, minor);
            return _version.Value;
        }
    }

    public bool IsArchSupported(Architecture architecture)
    {
        return Native.uc_arch_supported((int) architecture);
    }

    public unsafe ulong Query(QueryType type)
    {
        this.EnsureEngine();
        nuint value = 0;
        var result = Native.uc_query(_engine, (int) type, &value);
        this.CheckResult(result);
        return value;
    }

    #endregion

    #region Register IO

    public void RegWrite<T>(int registerId, T value) where T : unmanaged
    {
        this.EnsureEngine();
        int result;

        unsafe
        {
            result = Native.uc_reg_write(_engine, registerId, &value);
        }

        this.CheckResult(result);
    }

    public T RegRead<T>(int registerId) where T : unmanaged
    {
        this.EnsureEngine();
        int result;
        T value;

        unsafe
        {
            result = Native.uc_reg_read(_engine, registerId, &value);
        }

        this.CheckResult(result);
        return value;
    }

    public unsafe void RegBatchWrite<T>(int[] registerIds, IEnumerable<T> values) where T : unmanaged
    {
        this.EnsureEngine();

        var valuesArray = stackalloc T[registerIds.Length];
        var pointersToValues = stackalloc void*[registerIds.Length];

        var i = 0;
        foreach (var value in values)
        {
            valuesArray[i] = value;
            pointersToValues[i] = &valuesArray[i++];

            if (i == registerIds.Length)
                break;
        }

        if (i != registerIds.Length)
            throw new ArgumentException($"Expected {registerIds.Length} values, got {i}.", nameof(values));

        int result;
        fixed (int* regIdsPtr = &registerIds[0])
        {
            result = Native.uc_reg_write_batch(_engine, regIdsPtr, pointersToValues, registerIds.Length);
        }

        this.CheckResult(result);
    }

    public unsafe void RegBatchWrite<T>(int[] registerIds, Span<T> values) where T : unmanaged
    {
        this.EnsureEngine();

        if (values.Length != registerIds.Length)
            throw new ArgumentException($"Expected {registerIds.Length} values, got {values.Length}.", nameof(values));

        var pointersToValues = stackalloc void*[registerIds.Length];
        int result;

        fixed (T* valuesPinned = values)
        {
            for (var i = 0; i < registerIds.Length; i++)
            {
                pointersToValues[i] = &valuesPinned[i];
            }

            fixed (int* regIdsPtr = &registerIds[0])
            {
                result = Native.uc_reg_write_batch(_engine, regIdsPtr, pointersToValues, registerIds.Length);
            }
        }

        this.CheckResult(result);
    }

    public unsafe void RegBatchRead<T>(int[] registerIds, Span<T> target) where T : unmanaged
    {
        this.EnsureEngine();

        var pointersToValues = stackalloc void*[registerIds.Length];
        int result;

        fixed (T* targetPinned = target)
        {
            for (var i = 0; i < target.Length; i++)
            {
                pointersToValues[i] = &targetPinned[i];
            }

            fixed (int* regIdsPinned = &registerIds[0])
            {
                result = Native.uc_reg_read_batch(_engine, regIdsPinned, pointersToValues, registerIds.Length);
            }
        }

        this.CheckResult(result);
    }

    public unsafe T[] RegBatchRead<T>(int[] registerIds) where T : unmanaged
    {
        this.EnsureEngine();

        var pointersToValues = stackalloc void*[registerIds.Length];
        var retArray = new T[registerIds.Length];
        int result;

        fixed (T* targetPinned = retArray)
        {
            for (var i = 0; i < registerIds.Length; i++)
            {
                pointersToValues[i] = &targetPinned[i];
            }

            fixed (int* regIdsPinned = &registerIds[0])
            {
                result = Native.uc_reg_read_batch(_engine, regIdsPinned, pointersToValues, registerIds.Length);
            }
        }

        this.CheckResult(result);
        return retArray;
    }

    #endregion

    #region Engine control

    public unsafe int CurrentMode
    {
        get
        {
            this.EnsureEngine();
            var value = 0;
            var result = Native.uc_ctl(_engine, MakeReadControlType(1, UniConst.Ctl.Mode), &value);
            this.CheckResult(result);
            return value;
        }
    }

    public unsafe uint CurrentPageSize
    {
        get
        {
            this.EnsureEngine();
            var value = 0u;
            var result = Native.uc_ctl(_engine, MakeReadControlType(1, UniConst.Ctl.PageSize), &value);
            this.CheckResult(result);
            return value;
        }
        set
        {
            this.EnsureEngine();
            var result = Native.uc_ctl(_engine, MakeWriteControlType(1, UniConst.Ctl.PageSize), value);
            this.CheckResult(result);
        }
    }

    public unsafe int CurrentArch
    {
        get
        {
            this.EnsureEngine();
            var value = 0;
            var result = Native.uc_ctl(_engine, MakeReadControlType(1, UniConst.Ctl.Arch), &value);
            this.CheckResult(result);
            return value;
        }
    }

    public unsafe ulong CurrentTimeout
    {
        get
        {
            this.EnsureEngine();
            var value = 0ul;
            var result = Native.uc_ctl(_engine, MakeReadControlType(1, UniConst.Ctl.Timeout), &value);
            this.CheckResult(result);
            return value;
        }
    }

    public void EnableMultipleExits()
    {
        this.EnsureEngine();
        var result = Native.uc_ctl(_engine, MakeReadControlType(1, UniConst.Ctl.UseExits), 1);
        this.CheckResult(result);
    }

    public unsafe nuint CurrentNumberOfExits
    {
        get
        {
            this.EnsureEngine();
            nuint value = 0;
            var result = Native.uc_ctl(_engine, MakeReadControlType(1, UniConst.Ctl.ExitsCnt), &value);
            this.CheckResult(result);
            return value;
        }
    }

    public unsafe ulong[] Exits
    {
        get
        {
            var currentCount = this.CurrentNumberOfExits;
            var exits = new ulong[currentCount];

            int result;
            fixed (ulong* exitsPinned = exits)
            {
                result = Native.uc_ctl(_engine, MakeReadControlType(2, UniConst.Ctl.Exits), exitsPinned, currentCount);
            }

            this.CheckResult(result);
            return exits;
        }

        set
        {
            this.EnsureEngine();

            int result;
            fixed (ulong* exitsPinned = value)
            {
                result = Native.uc_ctl(_engine, MakeReadControlType(2, UniConst.Ctl.Exits), exitsPinned,
                    (nuint) value.Length);
            }

            this.CheckResult(result);
        }
    }

    public unsafe int CpuModel
    {
        get
        {
            this.EnsureEngine();
            var value = 0;
            var result = Native.uc_ctl(_engine, MakeReadControlType(1, UniConst.Ctl.CpuModel), &value);
            this.CheckResult(result);
            return value;
        }
        set
        {
            this.EnsureEngine();
            var result = Native.uc_ctl(_engine, MakeWriteControlType(1, UniConst.Ctl.CpuModel), value);
            this.CheckResult(result);
        }
    }

    #endregion

    #region Memory IO

    public void MemWrite(ulong address, byte[] bytes)
    {
        this.EnsureEngine();
        var result = Native.uc_mem_write(_engine, address, bytes, (nuint) bytes.Length);
        this.CheckResult(result);
    }

    public void MemWrite(ulong address, byte[] bytes, nuint size)
    {
        if (size > (nuint) bytes.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(size),
                $"{nameof(size)} cannot be more than the length of {nameof(bytes)}.");
        }

        this.EnsureEngine();
        var result = Native.uc_mem_write(_engine, address, bytes, size);
        this.CheckResult(result);
    }

    public unsafe void MemWrite(ulong address, Span<byte> bytes)
    {
        this.EnsureEngine();

        int result;
        fixed (byte* bytesFixed = bytes)
        {
            result = Native.uc_mem_write(_engine, address, bytesFixed, (nuint) bytes.Length);
        }

        this.CheckResult(result);
    }

    public unsafe void MemWrite(ulong address, Span<byte> bytes, nuint size)
    {
        if (size > (nuint) bytes.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(size),
                $"{nameof(size)} cannot be more than the length of {nameof(bytes)}.");
        }

        this.EnsureEngine();

        int result;
        fixed (byte* bytesFixed = bytes)
        {
            result = Native.uc_mem_write(_engine, address, bytesFixed, size);
        }

        this.CheckResult(result);
    }

    public byte[] MemRead(ulong address, nuint size)
    {
        this.EnsureEngine();
        var ret = new byte[size];
        var result = Native.uc_mem_read(_engine, address, ret, size);
        this.CheckResult(result);
        return ret;
    }

    public void MemRead(ulong address, byte[] target)
    {
        this.MemRead(address, target, (nuint) target.Length);
    }

    public void MemRead(ulong address, byte[] target, nuint size)
    {
        if (size > (nuint) target.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(size),
                $"{nameof(size)} cannot be more than the length of {nameof(target)}.");
        }

        this.EnsureEngine();
        var result = Native.uc_mem_read(_engine, address, target, size);
        this.CheckResult(result);
    }

    public void MemRead(ulong address, Span<byte> target)
    {
        this.MemRead(address, target, (nuint) target.Length);
    }

    public unsafe void MemRead(ulong address, Span<byte> target, nuint size)
    {
        if (size > (nuint) target.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(size),
                $"{nameof(size)} cannot be more than the length of {nameof(target)}.");
        }

        this.EnsureEngine();
        int result;
        fixed (byte* targetPinned = target)
        {
            result = Native.uc_mem_read(_engine, address, targetPinned, size);
        }

        this.CheckResult(result);
    }

    #endregion

    #region Emulation control

    public void EmuStart(ulong start, ulong until = 0, ulong timeout = 0, ulong count = 0)
    {
        this.EnsureEngine();
        var result = Native.uc_emu_start(_engine, start, until, timeout, (nuint) count);
        this.CheckResult(result);
    }

    public void EmuStop()
    {
        this.EnsureEngine();
        var result = Native.uc_emu_stop(_engine);
        this.CheckResult(result);
    }

    #endregion

    #region Internal hook callback delegates

    private CodeHookNativeCallback? _codeHookNativeDelegate;

    private InterruptHookNativeCallback? _interruptNativeDelegate;

    private InvalidInstructionHookNativeCallback? _invalidInstructionNativeDelegate;

    private MemoryHookNativeCallback? _memoryNativeDelegate;

    private InvalidMemoryAccessNativeCallback? _invalidAccessNativeDelegate;

    private MMIOReadNativeCallback? _mmioReadNativeDelegate;

    private MMIOWriteNativeCallback? _mmioWriteNativeDelegate;

    #endregion

    #region Internal hook callback methods

    private void CodeHookHandler(UIntPtr engine, ulong address, uint size, IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId] as CodeHookCallback;
        target?.Invoke(this, address, size);
    }

    private void InterruptHookHandler(UIntPtr engine, uint interruptNumber, IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId] as InterruptHookCallback;
        target?.Invoke(this, interruptNumber);
    }

    private bool InvalidInstructionHookHandler(UIntPtr engine, IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId] as InvalidInstructionHookCallback;
        return target?.Invoke(this) ??
               throw new InvalidOperationException("Invalid instruction hook callback not found.");
    }

    private void MemoryHookHandler(UIntPtr engine, int type, ulong address, int size, long value,
        IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId] as MemoryHookCallback;
        target?.Invoke(this, (MemoryAccessType) type, address, size, value);
    }

    private bool InvalidMemoryAccessHookHandler(UIntPtr engine, int type, ulong address, int size, long value,
        IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId] as InvalidMemoryAccessCallback;
        return target?.Invoke(this, (MemoryAccessType) type, address, size, value) ??
               throw new InvalidOperationException("Invalid memory access hook callback not found.");
    }

    private ulong MMIOReadHandler(UIntPtr engine, ulong offset, uint size, IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId] as MMIOReadCallback;
        return target?.Invoke(this, offset, size) ?? throw new InvalidOperationException();
    }

    private void MMIOWriteHandler(UIntPtr engine, ulong offset, uint size, ulong value, IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId] as MMIOWriteCallback;
        target?.Invoke(this, offset, size, value);
    }

    #endregion

    #region Hook adding

    private unsafe void AddHook(int type, Delegate nativeCallback, Delegate managedCallback,
        ulong startAddress, ulong endAddress)
    {
        this.EnsureEngine();

        if (!_nativeHooks.TryGetValue(nativeCallback, out var ptr))
        {
            ptr = Marshal.GetFunctionPointerForDelegate(nativeCallback);
            _nativeHooks.Add(nativeCallback, ptr);
        }

        nuint hookId = 0;

        var nextId = new IntPtr(_managedHooks.Count);
        _managedHooks.Add(managedCallback);
        _hookIdsForDelegates[managedCallback] = hookId;

        var result = Native.uc_hook_add(_engine, &hookId, type, ptr, nextId,
            startAddress, endAddress);

        this.CheckResult(result);
    }

    public void AddCodeHook(CodeHookCallback callback, ulong startAddress, ulong endAddress)
    {
        _codeHookNativeDelegate ??= this.CodeHookHandler;
        this.AddHook(UniConst.Hook.Code, _codeHookNativeDelegate,
            callback, startAddress, endAddress);
    }

    public void AddBlockHook(CodeHookCallback callback, ulong startAddress, ulong endAddress)
    {
        _codeHookNativeDelegate ??= this.CodeHookHandler;
        this.AddHook(UniConst.Hook.Block, _codeHookNativeDelegate,
            callback, startAddress, endAddress);
    }

    public void AddInterruptHook(InterruptHookCallback callback, ulong startAddress, ulong endAddress)
    {
        _interruptNativeDelegate ??= this.InterruptHookHandler;
        this.AddHook(UniConst.Hook.Intr, _interruptNativeDelegate,
            callback, startAddress, endAddress);
    }

    public void AddInvalidInstructionHook(InvalidInstructionHookCallback callback, ulong startAddress, ulong endAddress)
    {
        _invalidInstructionNativeDelegate ??= this.InvalidInstructionHookHandler;
        this.AddHook(UniConst.Hook.InsnInvalid, _invalidInstructionNativeDelegate,
            callback, startAddress, endAddress);
    }

    public void AddMemoryHook(MemoryHookCallback callback, MemoryHookType hookType, ulong startAddress,
        ulong endAddress)
    {
        _memoryNativeDelegate = this.MemoryHookHandler;
        this.AddHook((int) hookType, _memoryNativeDelegate, callback, startAddress, endAddress);
    }

    public void AddInvalidMemoryAccessHook(InvalidMemoryAccessCallback callback, MemoryHookType hookType,
        ulong startAddress, ulong endAddress)
    {
        _invalidAccessNativeDelegate = this.InvalidMemoryAccessHookHandler;
        this.AddHook((int) hookType, _invalidAccessNativeDelegate, callback, startAddress, endAddress);
    }

    #endregion

    #region Hook removing

    private void RemoveHook(Delegate callback)
    {
        if (!_hookIdsForDelegates.Remove(callback, out var hookId))
            return;

        this.EnsureEngine();
        var result = Native.uc_hook_del(_engine, hookId);
        _managedHooks.Remove(callback);
        this.CheckResult(result);
    }

    public void RemoveHook(CodeHookCallback callback)
    {
        this.RemoveHook((Delegate) callback);
    }

    public void RemoveHook(InterruptHookCallback callback)
    {
        this.RemoveHook((Delegate) callback);
    }

    public void RemoveHook(InvalidInstructionHookCallback callback)
    {
        this.RemoveHook((Delegate) callback);
    }

    public void RemoveHook(MemoryHookCallback callback)
    {
        this.RemoveHook((Delegate) callback);
    }

    public void RemoveHook(InvalidMemoryAccessCallback callback)
    {
        this.RemoveHook((Delegate) callback);
    }

    #endregion

    #region Memory mapping

    public void MemMap(ulong address, nuint size, MemoryPermissions permissions)
    {
        this.EnsureEngine();
        var result = Native.uc_mem_map(_engine, address, size, (uint) permissions);
        this.CheckResult(result);
    }

    public void MemMap(ulong address, nuint size, MemoryPermissions permissions, IntPtr memoryPointer)
    {
        this.EnsureEngine();
        var result = Native.uc_mem_map_ptr(_engine, address, size, (uint) permissions, memoryPointer);
        this.CheckResult(result);
    }

    public void MemMap(ulong address, nuint size, MMIOReadCallback readCallback, MMIOWriteCallback writeCallback)
    {
        this.EnsureEngine();

        _mmioReadNativeDelegate ??= this.MMIOReadHandler;
        _mmioWriteNativeDelegate ??= this.MMIOWriteHandler;

        if (!_nativeHooks.TryGetValue(_mmioReadNativeDelegate, out var readPtr))
        {
            readPtr = Marshal.GetFunctionPointerForDelegate(_mmioReadNativeDelegate);
        }

        if (!_nativeHooks.TryGetValue(_mmioWriteNativeDelegate, out var writePtr))
        {
            writePtr = Marshal.GetFunctionPointerForDelegate(_mmioWriteNativeDelegate);
        }

        var nextId = _managedHooks.Count;
        _managedHooks.Add(readCallback);
        _managedHooks.Add(writeCallback);

        var result = Native.uc_mmio_map(_engine, address, size, readPtr, new IntPtr(nextId),
            writePtr, new IntPtr(nextId + 1));

        this.CheckResult(result);
    }

    public void MemUnmap(ulong address, nuint size)
    {
        this.EnsureEngine();
        var result = Native.uc_mem_unmap(_engine, address, size);
        this.CheckResult(result);
    }

    #endregion

    #region Contexts

    public unsafe IUnicornContext MakeEmptyContext()
    {
        this.EnsureEngine();
        UIntPtr ptr = new();
        var result = Native.uc_context_alloc(_engine, &ptr);
        this.CheckResult(result);

        var contextObj = new UnicornContext(this, ptr);
        _contexts.Add(contextObj);
        return contextObj;
    }

    public IUnicornContext SaveContext()
    {
        var context = this.MakeEmptyContext();
        this.SaveContext(context);
        return context;
    }

    private UnicornContext CheckContext(IUnicornContext context)
    {
        if (context is not UnicornContext contextObj || contextObj.Unicorn != this)
            throw new InvalidOperationException("Only contexts created from this Unicorn instance may be used.");

        if (contextObj.Disposed)
            throw new ObjectDisposedException(nameof(UnicornContext),
                "This Unicorn context has already been disposed.");

        return contextObj;
    }

    public void SaveContext(IUnicornContext context)
    {
        this.EnsureEngine();
        var contextObj = this.CheckContext(context);
        var result = Native.uc_context_save(_engine, contextObj.Context);
        this.CheckResult(result);
    }

    public void RestoreContext(IUnicornContext context)
    {
        this.EnsureEngine();
        var contextObj = this.CheckContext(context);
        var result = Native.uc_context_restore(_engine, contextObj.Context);
        this.CheckResult(result);
    }

    #endregion

    #region Disposal

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            foreach (var context in _contexts)
            {
                context.Dispose();
            }

            _contexts.Clear();
            _nativeHooks.Clear();
            _managedHooks.Clear();
            _hookIdsForDelegates.Clear();
        }

        if (_engine != UIntPtr.Zero)
        {
            // TODO: Remove allocated memory for hooks etc.

            _ = Native.uc_close(_engine);
            _engine = UIntPtr.Zero;
            // Best effort: If closing failed, we can't really do anything about it
        }

        _disposed = true;
    }

    ~Unicorn()
    {
        this.Dispose(false);
    }

    #endregion
}

internal class UnicornContext : IUnicornContext
{
    public Unicorn Unicorn { get; }
    public UIntPtr Context { get; }
    internal bool Disposed;

    public UnicornContext(Unicorn unicorn, UIntPtr contextPtr)
    {
        this.Unicorn = unicorn;
        this.Context = contextPtr;
    }

    private void EnsureNotDisposed()
    {
        this.Unicorn.EnsureEngine();

        if (Disposed)
            throw new ObjectDisposedException(nameof(UnicornContext),
                "This Unicorn context has already been disposed.");
    }

    public void RegWrite<T>(int registerId, T value) where T : unmanaged
    {
        this.EnsureNotDisposed();
        int result;

        unsafe
        {
            result = Native.uc_context_reg_write(this.Context, registerId, &value);
        }

        this.Unicorn.CheckResult(result);
    }

    public T RegRead<T>(int registerId) where T : unmanaged
    {
        this.EnsureNotDisposed();
        int result;
        T value;

        unsafe
        {
            result = Native.uc_context_reg_read(this.Context, registerId, &value);
        }

        this.Unicorn.CheckResult(result);
        return value;
    }

    public unsafe void RegBatchWrite<T>(int[] registerIds, IEnumerable<T> values) where T : unmanaged
    {
        this.EnsureNotDisposed();

        var valuesArray = stackalloc T[registerIds.Length];
        var pointersToValues = stackalloc void*[registerIds.Length];

        var i = 0;
        foreach (var value in values)
        {
            valuesArray[i] = value;
            pointersToValues[i] = &valuesArray[i++];

            if (i == registerIds.Length)
                break;
        }

        if (i != registerIds.Length)
            throw new ArgumentException($"Expected {registerIds.Length} values, got {i}.", nameof(values));

        int result;
        fixed (int* regIdsPtr = &registerIds[0])
        {
            result = Native.uc_context_reg_write_batch(this.Context, regIdsPtr, pointersToValues, registerIds.Length);
        }

        this.Unicorn.CheckResult(result);
    }

    public unsafe void RegBatchWrite<T>(int[] registerIds, Span<T> values) where T : unmanaged
    {
        this.EnsureNotDisposed();

        if (values.Length != registerIds.Length)
            throw new ArgumentException($"Expected {registerIds.Length} values, got {values.Length}.", nameof(values));

        var pointersToValues = stackalloc void*[registerIds.Length];
        int result;

        fixed (T* valuesPinned = values)
        {
            for (var i = 0; i < registerIds.Length; i++)
            {
                pointersToValues[i] = &valuesPinned[i];
            }

            fixed (int* regIdsPtr = &registerIds[0])
            {
                result = Native.uc_context_reg_write_batch(this.Context, regIdsPtr, pointersToValues,
                    registerIds.Length);
            }
        }

        this.Unicorn.CheckResult(result);
    }

    public unsafe void RegBatchRead<T>(int[] registerIds, Span<T> target) where T : unmanaged
    {
        this.EnsureNotDisposed();

        var pointersToValues = stackalloc void*[registerIds.Length];
        int result;

        fixed (T* targetPinned = target)
        {
            for (var i = 0; i < target.Length; i++)
            {
                pointersToValues[i] = &targetPinned[i];
            }

            fixed (int* regIdsPinned = &registerIds[0])
            {
                result = Native.uc_context_reg_read_batch(this.Context, regIdsPinned, pointersToValues,
                    registerIds.Length);
            }
        }

        this.Unicorn.CheckResult(result);
    }

    public unsafe T[] RegBatchRead<T>(int[] registerIds) where T : unmanaged
    {
        this.EnsureNotDisposed();

        var pointersToValues = stackalloc void*[registerIds.Length];
        var retArray = new T[registerIds.Length];
        int result;

        fixed (T* targetPinned = retArray)
        {
            for (var i = 0; i < registerIds.Length; i++)
            {
                pointersToValues[i] = &targetPinned[i];
            }

            fixed (int* regIdsPinned = &registerIds[0])
            {
                result = Native.uc_context_reg_read_batch(this.Context, regIdsPinned, pointersToValues,
                    registerIds.Length);
            }
        }

        this.Unicorn.CheckResult(result);
        return retArray;
    }

    #region Disposal

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (Disposed)
            return;

        if (disposing)
        {
            // Dispose managed objects
            // Intentionally left blank
        }

        _ = Native.uc_context_free(this.Context);
        // Best effort: If closing failed, we can't really do anything about it

        Disposed = true;
    }

    ~UnicornContext()
    {
        this.Dispose(false);
    }

    #endregion
}