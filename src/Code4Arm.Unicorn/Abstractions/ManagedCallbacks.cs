// ReSharper disable InconsistentNaming

using Code4Arm.Unicorn.Abstractions.Enums;

namespace Code4Arm.Unicorn.Abstractions;

// uc_cb_hookcode_t
public delegate void CodeHookCallback(IUnicorn engine, ulong address, uint size);

// uc_cb_hookintr_t
public delegate void InterruptHookCallback(IUnicorn engine, uint interruptNumber);

// uc_cb_hookinsn_invalid_t
public delegate bool InvalidInstructionHookCallback(IUnicorn engine);

// Missing: uc_cb_insn_in_t
// Missing: uc_cb_insn_out_t
// Missing: uc_hook_edge_gen_t
// Missing: uc_hook_tcg_op_2

// uc_cb_mmio_read_t
public delegate ulong MMIOReadCallback(IUnicorn engine, ulong offset, uint size);

// uc_cb_mmio_write_t
public delegate void MMIOWriteCallback(IUnicorn engine, ulong offset, uint size, ulong value);

// uc_cb_hookmem_t
public delegate void MemoryHookCallback(IUnicorn engine, MemoryAccessType memoryAccessType,
    ulong address, int size, long value);

// uc_cb_eventmem_t
public delegate bool InvalidMemoryAccessCallback(IUnicorn engine, MemoryAccessType memoryAccessType,
    ulong address, int size, long value);
