// ManagedCallbacks.cs
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

using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;

// ReSharper disable CheckNamespace
// ReSharper disable InconsistentNaming

namespace Code4Arm.Unicorn.Callbacks;

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
