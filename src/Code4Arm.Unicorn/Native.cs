using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming

namespace Code4Arm.Unicorn;

internal static class Native
{
    private const string LibName = "unicorn";

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_version(uint* major, uint* minor);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern bool uc_arch_supported(int arch);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_open(int arch, int mode, UIntPtr* engine);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_close(UIntPtr eng);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_query(UIntPtr eng, int type, nuint* result);

    #region uc_ctl overloads

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_ctl")]
    public static extern int uc_ctl(UIntPtr eng, int control, int arg0);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_ctl")]
    public static extern int uc_ctl(UIntPtr eng, int control, uint arg0);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_ctl")]
    public static extern unsafe int uc_ctl(UIntPtr eng, int control, int* arg0);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_ctl")]
    public static extern unsafe int uc_ctl(UIntPtr eng, int control, uint* arg0);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_ctl")]
    public static extern unsafe int uc_ctl(UIntPtr eng, int control, ulong* arg0);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_ctl")]
    public static extern unsafe int uc_ctl(UIntPtr eng, int control, nuint* arg0);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_ctl")]
    public static extern unsafe int uc_ctl(UIntPtr eng, int control, ulong* arg0, nuint arg1);

    #endregion

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_errno(UIntPtr eng);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr uc_strerror(int err);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_reg_write(UIntPtr eng, int regId, void* value);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_reg_read(UIntPtr eng, int regId, void* value);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_reg_write_batch(UIntPtr eng, int* regs, void** values, int count);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_reg_read_batch(UIntPtr eng, int* regs, void** values, int count);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_mem_write(UIntPtr eng, ulong address, byte[] value, nuint size);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_mem_write(UIntPtr eng, ulong address, byte* value, nuint size);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_mem_read(UIntPtr eng, ulong address, byte[] value, nuint size);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_mem_read(UIntPtr eng, ulong address, byte* value, nuint size);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_emu_start(UIntPtr eng, ulong beginAddr, ulong untilAddr, ulong timeout,
        nuint count);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_emu_stop(UIntPtr eng);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, EntryPoint = "uc_hook_add")]
    public static extern unsafe int uc_hook_add(UIntPtr eng, nuint* hookId, int callbackType, IntPtr callback,
        IntPtr userData, ulong beginAddress, ulong endAddress);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_hook_add(UIntPtr eng, nuint* hookId, int callbackType, IntPtr callback,
        IntPtr userData, ulong beginAddress, ulong endAddress, int arg0);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_hook_add(UIntPtr eng, nuint* hookId, int callbackType, IntPtr callback,
        IntPtr userData, ulong beginAddress, ulong endAddress, ulong arg0, ulong arg1);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_hook_del(UIntPtr eng, nuint hookId);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_mem_map(UIntPtr eng, ulong address, nuint size, uint perm);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_mem_map_ptr(UIntPtr eng, ulong address, nuint size, uint perm, IntPtr ptr);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_mmio_map(UIntPtr eng, ulong address, nuint size, IntPtr readCallback,
        IntPtr userDataRead, IntPtr writeCallback, IntPtr userDataWrite);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_mem_unmap(UIntPtr eng, ulong address, nuint size);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_mem_protect(UIntPtr eng, ulong address, nuint size, uint perms);

    // Missing: uc_mem_regions

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_context_alloc(UIntPtr eng, UIntPtr* contextTarget);

    // Missing: uc_free    

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_context_save(UIntPtr uc, UIntPtr context);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_context_reg_write(UIntPtr context, int regId, void* value);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_context_reg_read(UIntPtr context, int regId, void* value);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_context_reg_write_batch(UIntPtr context, int* regs, void** values, int count);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern unsafe int uc_context_reg_read_batch(UIntPtr context, int* regs, void** values, int count);

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_context_restore(UIntPtr eng, UIntPtr context);

    // Missing: uc_context_size

    [DllImport(LibName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_context_free(UIntPtr context);
}

// typedef void (*uc_cb_hookcode_t)(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void CodeHookNativeCallback(UIntPtr engine, ulong address, uint size, IntPtr userData);

// typedef void (*uc_cb_hookintr_t)(uc_engine *uc, uint32_t intno, void *user_data);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void InterruptHookNativeCallback(UIntPtr engine, uint interruptNumber, IntPtr userData);

// typedef bool (*uc_cb_hookinsn_invalid_t)(uc_engine *uc, void *user_data);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate bool InvalidInstructionHookNativeCallback(UIntPtr engine, IntPtr userData);

// Missing: uc_cb_insn_in_t
// Missing: uc_cb_insn_out_t
// Missing: uc_hook_edge_gen_t
// Missing: uc_hook_tcg_op_2

// typedef uint64_t (*uc_cb_mmio_read_t)(uc_engine *uc, uint64_t offset, unsigned size, void *user_data);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate ulong MMIOReadNativeCallback(UIntPtr engine, ulong offset, uint size, IntPtr userData);

// typedef void (*uc_cb_mmio_write_t)(uc_engine *uc, uint64_t offset, unsigned size, uint64_t value, void *user_data);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void MMIOWriteNativeCallback(UIntPtr engine, ulong offset, uint size, ulong value, IntPtr userData);

// typedef void (*uc_cb_hookmem_t)(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void MemoryHookNativeCallback(UIntPtr engine, int type, ulong address, int size, long value,
    IntPtr userData);

// typedef bool (*uc_cb_eventmem_t)(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate bool InvalidMemoryAccessNativeCallback(UIntPtr engine, int type, ulong address, int size, long value,
    IntPtr userData);