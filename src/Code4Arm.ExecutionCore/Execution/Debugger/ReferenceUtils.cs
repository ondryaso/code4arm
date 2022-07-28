﻿// ReferenceUtils.cs
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

using System.Runtime.CompilerServices;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public enum ContainerType : uint
{
    Registers = 1,
    ControlRegisters,
    SimdRegisters,
    Symbols,
    Stack,

    RegisterSubtypes,
    RegisterSubtypesValues,
    SimdRegisterSubtypes,
    SimdRegisterSubtypesValues,

    ControlFlags,

    StackSubtypes,
    StackSubtypesValues,
    
    SymbolAddress,

    ExpressionExtras
}

internal static class ReferenceUtils
{
    public static long MakeReference(ContainerType containerType, int regId = 0, DebuggerVariableType subtype = 0,
        int simdLevel = 0, int evaluateId = 0)
    {
        var ret = (((ulong)containerType) & 0xF) | ((((ulong)subtype) & 0xF) << 4) | ((((ulong)regId) & 0xFF) << 8)
            | ((((ulong)simdLevel) & 0x3) << 16) | ((((ulong)evaluateId) & 0xFF) << 40);

        return Unsafe.As<ulong, long>(ref ret);
    }

    public static long MakeReference(ContainerType containerType, uint address, DebuggerVariableType subtype = 0,
        int evaluateId = 0)
    {
        var ret = (((ulong)containerType) & 0xF) | ((((ulong)subtype) & 0xF) << 4) | (((ulong)address) << 8)
            | ((((ulong)evaluateId) & 0xFF) << 40);

        return Unsafe.As<ulong, long>(ref ret);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static bool IsTopLevelContainer(long variablesReference)
        => (variablesReference & 0xF) == variablesReference;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ContainerType GetContainerType(long variablesReference)
        => (ContainerType)(variablesReference & 0xF);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetRegisterId(long variablesReference)
        => unchecked((int)((((ulong)variablesReference) >> 8) & 0xFF));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int GetSimdLevel(long variablesReference)
        => unchecked((int)((((ulong)variablesReference) >> 16) & 0x3));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint GetTargetAddress(long variablesReference)
        => unchecked((uint)((((ulong)variablesReference) >> 8) & 0xFFFFFFFF));

    public static int GetEvaluateId(long variablesReference)
        => unchecked((int)((((ulong)variablesReference) >> 40) & 0xFF));
}
