// NativeCallbacks.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using System.Runtime.InteropServices;

// ReSharper disable InconsistentNaming
// ReSharper disable CheckNamespace

namespace Code4Arm.Unicorn.Callbacks.Native;

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
public delegate void MMIOWriteNativeCallback(UIntPtr engine, ulong offset, uint size, ulong value,
    IntPtr userData);

// typedef void (*uc_cb_hookmem_t)(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate void MemoryHookNativeCallback(UIntPtr engine, int type, ulong address, int size, long value,
    IntPtr userData);

// typedef bool (*uc_cb_eventmem_t)(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data);
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate bool InvalidMemoryAccessNativeCallback(UIntPtr engine, int type, ulong address, int size,
    long value,
    IntPtr userData);
