using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Callbacks;
using Code4Arm.Unicorn.Callbacks.Native;
using Code4Arm.Unicorn.Constants;
using Architecture = Code4Arm.Unicorn.Abstractions.Enums.Architecture;

// ReSharper disable InconsistentNaming

namespace Code4Arm.Unicorn;

public class Unicorn : IUnicorn
{
    public const int ApiMajor = 2, ApiMinor = 0, ApiPatch = 0, ApiExtra = 7;

    private readonly List<UnicornContext> _contexts = new();

    // Collections that keep hook references (both native and managed – the delegates mustn't be deleted by GC)
    private readonly Dictionary<int, UnicornHookRegistration> _managedHooks = new();
    private readonly Dictionary<Delegate, IntPtr> _nativeHookFunctionPointers = new(8);
    private readonly Dictionary<nuint, Delegate?> _customNativeHooks = new();

    private int _nextAddedManagedHookId;
    private readonly object HookAddingLocker = new();

    private bool _disposed;
    private UIntPtr _engine;

    public unsafe Unicorn(Architecture architecture, EngineMode mode)
    {
        var ptr = new UIntPtr();
        var result = Native.uc_open((int)architecture, (int)mode, &ptr);
        this.CheckResult(result);
        _engine = ptr;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int MakeReadControlType(int numberOfArgs, int controlType)
        => controlType | (numberOfArgs << 26) | (2 << 30);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int MakeWriteControlType(int numberOfArgs, int controlType)
        => controlType | (numberOfArgs << 26) | (1 << 30);

    #region Helpers

    internal void CheckResult(int result)
    {
        if (result == UniConst.Err.Ok) return;
        var resultMessagePtr = Native.uc_strerror(result);
        var resultMessage = Marshal.PtrToStringAnsi(resultMessagePtr);

        throw new UnicornException(result, $"{resultMessage}. Error code: {result}.");
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

    public bool IsArchSupported(Architecture architecture) => Native.uc_arch_supported((int)architecture);

    public unsafe ulong Query(QueryType type)
    {
        this.EnsureEngine();
        nuint value = 0;
        var result = Native.uc_query(_engine, (int)type, &value);
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

    public unsafe void RegRead<T>(int registerId, ref T target) where T : unmanaged
    {
        this.EnsureEngine();
        int result;

        fixed (void* value = &target)
        {
            result = Native.uc_reg_read(_engine, registerId, &value);
        }

        this.CheckResult(result);
    }

    public unsafe void RegWrite(int registerId, ReadOnlySpan<byte> bytes)
    {
        this.EnsureEngine();
        int result;

        fixed (byte* pinned = bytes)
        {
            result = Native.uc_reg_write(_engine, registerId, pinned);
        }

        this.CheckResult(result);
    }

    public unsafe void RegRead(int registerId, Span<byte> target)
    {
        this.EnsureEngine();
        int result;

        fixed (byte* pinned = target)
        {
            result = Native.uc_reg_read(_engine, registerId, pinned);
        }

        this.CheckResult(result);
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
        fixed (int* regIdsPtr = registerIds)
        {
            result = Native.uc_reg_write_batch(_engine, regIdsPtr, pointersToValues, registerIds.Length);
        }

        this.CheckResult(result);
    }

    public unsafe void RegBatchWrite<T>(int[] registerIds, ReadOnlySpan<T> values) where T : unmanaged
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

            fixed (int* regIdsPtr = registerIds)
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

            fixed (int* regIdsPinned = registerIds)
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

            fixed (int* regIdsPinned = registerIds)
            {
                result = Native.uc_reg_read_batch(_engine, regIdsPinned, pointersToValues, registerIds.Length);
            }
        }

        this.CheckResult(result);

        return retArray;
    }

    #endregion

    #region Engine control

    public bool CheckIfBindingMatchesLibrary(bool throwIfNot = false, bool considerMinor = true)
    {
        var (major, minor) = Version;
        var result = major == ApiMajor && (!considerMinor || minor == ApiMinor);

        if (throwIfNot && !result)
            throw new UnicornException((int)UnicornError.BindingVersionMismatch,
                $"Unicorn library version is {major}.{minor} while the binding was made for {ApiMajor}.{ApiMinor}.");

        return result;
    }

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
        var result = Native.uc_ctl(_engine, MakeWriteControlType(1, UniConst.Ctl.UseExits), 1);
        this.CheckResult(result);
    }

    public void RemoveTbCache(ulong begin, ulong end)
    {
        this.EnsureEngine();
        var result = Native.uc_ctl(_engine, MakeWriteControlType(2, UniConst.Ctl.TbRemoveCache), begin, end);
        this.CheckResult(result);
    }

    public unsafe void GetExits(Span<ulong> target)
    {
        var currentCount = CurrentNumberOfExits; // Calls EnsureEngine()

        if (target.Length < (int)currentCount)
            throw new InvalidOperationException($"Target span is not large enough for {currentCount} existing exits.");

        int result;
        fixed (ulong* exitsPinned = target)
        {
            result = Native.uc_ctl(_engine, MakeReadControlType(2, UniConst.Ctl.Exits), exitsPinned, currentCount);
        }

        this.CheckResult(result);
    }

    public void SetExits(ReadOnlySpan<ulong> exits)
    {
        this.SetExits(exits, exits.Length);
    }

    public unsafe void SetExits(ReadOnlySpan<ulong> exits, int length)
    {
        if (length < 0)
            throw new ArgumentException("Length must not be less than zero.", nameof(length));

        this.EnsureEngine();

        int result;
        fixed (ulong* exitsPinned = exits)
        {
            result = Native.uc_ctl(_engine, MakeWriteControlType(2, UniConst.Ctl.Exits), exitsPinned,
                (nuint)length);
        }

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
            var currentCount = CurrentNumberOfExits; // Calls EnsureEngine()
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
                result = Native.uc_ctl(_engine, MakeWriteControlType(2, UniConst.Ctl.Exits), exitsPinned,
                    (nuint)value.Length);
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
        var result = Native.uc_mem_write(_engine, address, bytes, (nuint)bytes.Length);
        this.CheckResult(result);
    }

    public void MemWrite(ulong address, byte[] bytes, nuint size)
    {
        if (size > (nuint)bytes.Length)
            throw new ArgumentOutOfRangeException(nameof(size),
                $"{nameof(size)} cannot be more than the length of {nameof(bytes)}.");

        this.EnsureEngine();
        var result = Native.uc_mem_write(_engine, address, bytes, size);
        this.CheckResult(result);
    }

    public unsafe void MemWrite(ulong address, ReadOnlySpan<byte> bytes)
    {
        this.EnsureEngine();

        int result;
        fixed (byte* bytesFixed = bytes)
        {
            result = Native.uc_mem_write(_engine, address, bytesFixed, (nuint)bytes.Length);
        }

        this.CheckResult(result);
    }

    public unsafe void MemWrite(ulong address, ReadOnlySpan<byte> bytes, nuint size)
    {
        if (size > (nuint)bytes.Length)
            throw new ArgumentOutOfRangeException(nameof(size),
                $"{nameof(size)} cannot be more than the length of {nameof(bytes)}.");

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
        this.MemRead(address, target, (nuint)target.Length);
    }

    public void MemRead(ulong address, byte[] target, nuint size)
    {
        if (size > (nuint)target.Length)
            throw new ArgumentOutOfRangeException(nameof(size),
                $"{nameof(size)} cannot be more than the length of {nameof(target)}.");

        this.EnsureEngine();
        var result = Native.uc_mem_read(_engine, address, target, size);
        this.CheckResult(result);
    }

    public void MemRead(ulong address, Span<byte> target)
    {
        this.MemRead(address, target, (nuint)target.Length);
    }

    public unsafe void MemRead(ulong address, Span<byte> target, nuint size)
    {
        if (size > (nuint)target.Length)
            throw new ArgumentOutOfRangeException(nameof(size),
                $"{nameof(size)} cannot be more than the length of {nameof(target)}.");

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
        var result = Native.uc_emu_start(_engine, start, until, timeout, (nuint)count);
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
        var target = _managedHooks[targetId].Callback as CodeHookCallback;
        target?.Invoke(this, address, size);
    }

    private void InterruptHookHandler(UIntPtr engine, uint interruptNumber, IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId].Callback as InterruptHookCallback;
        target?.Invoke(this, interruptNumber);
    }

    private bool InvalidInstructionHookHandler(UIntPtr engine, IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId].Callback as InvalidInstructionHookCallback;

        return target?.Invoke(this) ??
            throw new InvalidOperationException("Invalid instruction hook callback not found.");
    }

    private void MemoryHookHandler(UIntPtr engine, int type, ulong address, int size, long value,
        IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId].Callback as MemoryHookCallback;
        target?.Invoke(this, (MemoryAccessType)type, address, size, value);
    }

    private bool InvalidMemoryAccessHookHandler(UIntPtr engine, int type, ulong address, int size, long value,
        IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId].Callback as InvalidMemoryAccessCallback;

        return target?.Invoke(this, (MemoryAccessType)type, address, size, value) ??
            throw new InvalidOperationException("Invalid memory access hook callback not found.");
    }

    private ulong MMIOReadHandler(UIntPtr engine, ulong offset, uint size, IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId].Callback as MMIOReadCallback;

        return target?.Invoke(this, offset, size) ?? throw new InvalidOperationException();
    }

    private void MMIOWriteHandler(UIntPtr engine, ulong offset, uint size, ulong value, IntPtr userData)
    {
        var targetId = userData.ToInt32();
        var target = _managedHooks[targetId].Callback as MMIOWriteCallback;
        target?.Invoke(this, offset, size, value);
    }

    #endregion

    #region Hook adding

    private unsafe UnicornHookRegistration AddHook(int type, Delegate nativeCallback, Delegate managedCallback,
        ulong startAddress, ulong endAddress)
    {
        this.EnsureEngine();
        int nextId;
        IntPtr nativeCallbackPtr;

        lock (HookAddingLocker)
        {
            if (!_nativeHookFunctionPointers.TryGetValue(nativeCallback, out nativeCallbackPtr))
            {
                nativeCallbackPtr = Marshal.GetFunctionPointerForDelegate(nativeCallback);
                _nativeHookFunctionPointers.Add(nativeCallback, nativeCallbackPtr);
            }

            nextId = _nextAddedManagedHookId++;
        }

        nuint hookId = 0;

        var result = Native.uc_hook_add(_engine, &hookId, type, nativeCallbackPtr, new IntPtr(nextId),
            startAddress, endAddress);

        this.CheckResult(result);

        var registration = new UnicornHookRegistration()
        {
            Callback = managedCallback,
            StartAddress = startAddress,
            EndAddress = endAddress,
            HookType = type,
            NativeHookId = hookId,
            ManagedHookId = nextId,
            Unicorn = this
        };

        _managedHooks.Add(nextId, registration);

        return registration;
    }

    public unsafe nuint AddNativeHook(IntPtr callbackPointer, int type, ulong startAddress, ulong endAddress,
        nint userData = 0)
    {
        this.EnsureEngine();

        nuint hookId = 0;
        var result = Native.uc_hook_add(_engine, &hookId, type, callbackPointer, userData,
            startAddress, endAddress);

        this.CheckResult(result);

        _customNativeHooks.Add(hookId, null);

        return hookId;
    }

    public unsafe nuint AddNativeHook(Delegate callback, int type, ulong startAddress, ulong endAddress,
        nint userData = 0)
    {
        this.EnsureEngine();

        var ptr = Marshal.GetFunctionPointerForDelegate(callback);

        nuint hookId = 0;
        var result = Native.uc_hook_add(_engine, &hookId, type, ptr, userData,
            startAddress, endAddress);

        this.CheckResult(result);

        _customNativeHooks.Add(hookId, callback);

        return hookId;
    }

    public UnicornHookRegistration AddCodeHook(CodeHookCallback callback, ulong startAddress, ulong endAddress)
    {
        _codeHookNativeDelegate ??= this.CodeHookHandler;

        return this.AddHook(UniConst.Hook.Code, _codeHookNativeDelegate,
            callback, startAddress, endAddress);
    }

    public UnicornHookRegistration AddBlockHook(CodeHookCallback callback, ulong startAddress, ulong endAddress)
    {
        _codeHookNativeDelegate ??= this.CodeHookHandler;

        return this.AddHook(UniConst.Hook.Block, _codeHookNativeDelegate,
            callback, startAddress, endAddress);
    }

    public UnicornHookRegistration AddInterruptHook(InterruptHookCallback callback)
    {
        _interruptNativeDelegate ??= this.InterruptHookHandler;

        // When invoking interrupt hook callbacks, Unicorn doesn't check for address bounds.
        // See cpu-exec.c -> cpu_handle_exception(CPUState *cpu, int *ret).
        return this.AddHook(UniConst.Hook.Intr, _interruptNativeDelegate,
            callback, 1, 0);
    }

    public UnicornHookRegistration AddInvalidInstructionHook(InvalidInstructionHookCallback callback)
    {
        _invalidInstructionNativeDelegate ??= this.InvalidInstructionHookHandler;

        // When invoking invalid instruction hook callbacks, Unicorn doesn't check for address bounds.
        // See cpu-exec.c -> cpu_handle_exception(CPUState *cpu, int *ret).
        return this.AddHook(UniConst.Hook.InsnInvalid, _invalidInstructionNativeDelegate,
            callback, 1, 0);
    }

    public UnicornHookRegistration AddMemoryHook(MemoryHookCallback callback, MemoryHookType hookType,
        ulong startAddress, ulong endAddress)
    {
        _memoryNativeDelegate = this.MemoryHookHandler;

        return this.AddHook((int)hookType, _memoryNativeDelegate, callback, startAddress, endAddress);
    }

    public UnicornHookRegistration AddInvalidMemoryAccessHook(InvalidMemoryAccessCallback callback,
        MemoryHookType hookType, ulong startAddress, ulong endAddress)
    {
        _invalidAccessNativeDelegate = this.InvalidMemoryAccessHookHandler;

        return this.AddHook((int)hookType, _invalidAccessNativeDelegate, callback, startAddress, endAddress);
    }

    #endregion

    #region Hook removing

    public void RemoveHook(UnicornHookRegistration registration)
    {
        if (!_managedHooks.Remove(registration.ManagedHookId, out var reg) || reg != registration)
            throw new ArgumentException(
                "The given registration was not made using this Unicorn instance or the hook has already been removed.",
                nameof(registration));

        this.EnsureEngine();
        var result = Native.uc_hook_del(_engine, registration.NativeHookId);
        this.CheckResult(result);
    }

    public void RemoveNativeHook(nuint hookId)
    {
        if (!_customNativeHooks.Remove(hookId))
            return;

        this.EnsureEngine();
        var result = Native.uc_hook_del(_engine, hookId);
        this.CheckResult(result);
    }

    #endregion

    #region Memory mapping

    public void MemMap(ulong address, nuint size, MemoryPermissions permissions)
    {
        this.EnsureEngine();
        var result = Native.uc_mem_map(_engine, address, size, (uint)permissions);
        this.CheckResult(result);
    }

    public void MemMap(ulong address, nuint size, MemoryPermissions permissions, IntPtr memoryPointer)
    {
        this.EnsureEngine();
        var result = Native.uc_mem_map_ptr(_engine, address, size, (uint)permissions, memoryPointer);
        this.CheckResult(result);
    }

    public void MemMap(ulong address, nuint size, MMIOReadCallback? readCallback, MMIOWriteCallback? writeCallback)
    {
        this.EnsureEngine();

        nint readPtr = 0, writePtr = 0, userDataRead = 0, userDataWrite = 0;
        int readId, writeId;

        lock (HookAddingLocker)
        {
            if (readCallback != null)
            {
                _mmioReadNativeDelegate ??= this.MMIOReadHandler;
                if (!_nativeHookFunctionPointers.TryGetValue(_mmioReadNativeDelegate, out readPtr))
                {
                    readPtr = Marshal.GetFunctionPointerForDelegate(_mmioReadNativeDelegate);
                    _nativeHookFunctionPointers.Add(_mmioReadNativeDelegate, readPtr);
                }
            }

            if (writeCallback != null)
            {
                _mmioWriteNativeDelegate ??= this.MMIOWriteHandler;
                if (!_nativeHookFunctionPointers.TryGetValue(_mmioWriteNativeDelegate, out writePtr))
                {
                    writePtr = Marshal.GetFunctionPointerForDelegate(_mmioWriteNativeDelegate);
                    _nativeHookFunctionPointers.Add(_mmioWriteNativeDelegate, writePtr);
                }
            }

            readId = _nextAddedManagedHookId++;
            writeId = _nextAddedManagedHookId++;
        }

        if (readCallback != null)
        {
            _managedHooks.Add(readId, new UnicornHookRegistration()
            {
                Callback = readCallback,
                StartAddress = address,
                EndAddress = address + size,
                NativeHookId = 0,
                ManagedHookId = readId,
                HookType = -1,
                Unicorn = this
            });

            userDataRead = new IntPtr(readId);
        }

        if (writeCallback != null)
        {
            _managedHooks.Add(writeId, new UnicornHookRegistration()
            {
                Callback = writeCallback,
                StartAddress = address,
                EndAddress = address + size,
                NativeHookId = 0,
                ManagedHookId = writeId,
                HookType = -1,
                Unicorn = this
            });

            userDataWrite = new IntPtr(writeId);
        }

        var result = Native.uc_mmio_map(_engine, address, size, readPtr, userDataRead,
            writePtr, userDataWrite);

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
        if (context is not UnicornContext contextObj || (contextObj.Unicorn != this))
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
            _nativeHookFunctionPointers.Clear();
            _managedHooks.Clear();
            _customNativeHooks.Clear();
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
