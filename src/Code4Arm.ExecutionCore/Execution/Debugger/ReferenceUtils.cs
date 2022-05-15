// ReferenceUtils.cs
// Author: Ondřej Ondryáš

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
    StackSubtypesValues
}

internal static class ReferenceUtils
{
    public static long MakeReference(ContainerType containerType, int regId = 0, DebuggerVariableType subtype = 0,
        int simdLevel = 0)
    {
        var ret = (((ulong)containerType) & 0xF) | ((((ulong)subtype) & 0xF) << 4) | ((((uint)regId) & 0xFF) << 8)
            | ((((uint)simdLevel) & 0x3) << 16);

        return Unsafe.As<ulong, long>(ref ret);
    }

    public static long MakeReference(ContainerType containerType, uint address, DebuggerVariableType subtype = 0)
    {
        var ret = (((ulong)containerType) & 0xF) | ((((ulong)subtype) & 0xF) << 4) | (((ulong)address) << 8);

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
}
