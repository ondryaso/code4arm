// AbiUtils.cs
// Author: Ondřej Ondryáš

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Environment;

public class AbiUtils
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int CeilTo(int value, int @base)
        => ((value + @base - 1) / @base) * @base;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint CeilTo(uint value, uint @base)
        => ((value + @base - 1) / @base) * @base;

    public static void GetReturnResult(IUnicorn unicorn, Span<byte> target, AbiType type)
    {
        switch (type)
        {
            case { Size: < 4 }:
            {
                // A Half-precision Floating Point Type is returned in the least significant 16 bits of r0.
                // A Fundamental Data Type that is smaller than 4 bytes is zero- or sign-extended to a word and returned
                // in r0.
                // A Composite Type not larger than 4 bytes is returned in r0.
                var r0 = unicorn.RegRead<uint>(Arm.Register.R0);
                var mask = unchecked((uint)((1 << ((type.Size * 8) + 1)) - 1));
                var masked = r0 & mask;
                var maskedSpan = MemoryMarshal.CreateSpan(ref masked, 1);
                var maskedBytes = MemoryMarshal.AsBytes(maskedSpan);
                maskedBytes[0..type.Size].CopyTo(target);

                // TODO: Big endian
                break;
            }
            case { Size: 4 }:
            {
                // A word-sized Fundamental Data Type (e.g., int, float) is returned in r0.
                // A Composite Type not larger than 4 bytes is returned in r0.
                var r0 = unicorn.RegRead<uint>(Arm.Register.R0);
                MemoryMarshal.Write(target, ref r0);

                break;
            }
            case { Size: 8 or 16, MachineType: not 0 }:
            {
                // A double-word sized Fundamental Data Type (e.g., long long, double and 64-bit containerized vectors)
                // is returned in r0 and r1.
                // A 128-bit containerized vector is returned in r0-r3.
                var regCount = type.Size / 4;
                Span<int> regs = stackalloc int[regCount];
                regs[0] = Arm.Register.R0;
                regs[1] = Arm.Register.R1;

                if (type.Size == 16)
                {
                    regs[2] = Arm.Register.R2;
                    regs[3] = Arm.Register.R3;
                }

                Span<uint> values = stackalloc uint[regCount];
                unicorn.RegBatchRead(regs, values);

                var valuesBytes = MemoryMarshal.Cast<uint, byte>(values);
                valuesBytes.CopyTo(target);

                break;
            }
            case { Size: > 4 }:
            {
                // A Composite Type larger than 4 bytes, or whose size cannot be determined statically by both caller
                // and callee, is stored in memory at an address passed as an extra argument when the function was called.
                var r0 = unicorn.RegRead<uint>(Arm.Register.R0);
                unicorn.MemRead(r0, target, (nuint)type.Size);

                break;
            }
        }
    }

    public static void GetReturnResult(IUnicorn unicorn, Span<byte> target, int size)
        => GetReturnResult(unicorn, target, new AbiType(size, size));

    public static AbiType[] AdjustParameterTypes(IList<AbiType> parameterTypes)
    {
        // https://github.com/ARM-software/abi-aa/blob/main/aapcs32/aapcs32.rst#parameter-passing
        // Stage B only

        var targetTypes = new AbiType[parameterTypes.Count];
        for (var i = 0; i < parameterTypes.Count; i++)
        {
            // B.1
            var inType = parameterTypes[i];
            if (inType.Size == 0)
                targetTypes[i] = AbiTypes.DataPointer;
            else
                targetTypes[i] = inType;

            // B.2 (+B.5)
            if (targetTypes[i].Class == AbiTypeClass.Integral && targetTypes[i].Size < 4)
                targetTypes[i] = targetTypes[i] with { Size = 4, Alignment = 4 };
            else if (targetTypes[i] == AbiTypes.HalfPrecision)
                targetTypes[i] = targetTypes[i] with { Size = 4, Alignment = 4 };

            // B.4
            if (targetTypes[i].MachineType == 0 && targetTypes[i].Size % 4 != 0)
                targetTypes[i] = targetTypes[i] with { Size = CeilTo(targetTypes[i].Size, 4) };

            // B.5
            if (targetTypes[i].MachineType == 0 && targetTypes[i].Alignment < 4)
                targetTypes[i] = targetTypes[i] with { Alignment = 4 };
            else if (targetTypes[i].MachineType == 0 && targetTypes[i].Alignment > 8)
                targetTypes[i] = targetTypes[i] with { Alignment = 8 };
        }

        return targetTypes;
    }
    
    public static void GetParameters(IUnicorn unicorn, Span<byte> target, bool returnsInMemory,
        AbiType[] adjustedParameterTypes)
    {
        // Stage A
        var ncrn = returnsInMemory ? 1 : 0;
        var targetIndex = 0;
        var targetTypes = adjustedParameterTypes;
        var stackPointerTop = unicorn.RegRead<uint>(Arm.Register.SP);
        var nsaa = stackPointerTop;

        // Stage C
        for (var i = 0; i < targetTypes.Length; i++)
        {
            var inType = targetTypes[i];
            // C.3
            if (inType.Alignment == 8)
                ncrn = CeilTo(ncrn, 2);

            // C.4
            if (inType.Size <= (4 - ncrn) * 4)
            {
                var rHigh = ncrn + (inType.Size / 4);
                for (var r = ncrn; r < rHigh; r++)
                {
                    var rVal = unicorn.RegRead<uint>(Arm.Register.GetRegister(r));
                    MemoryMarshal.Write(target[targetIndex..], ref rVal);
                    targetIndex += 4;
                }

                ncrn = rHigh;

                continue;
            }

            // C.5
            if (ncrn < 4 && nsaa == stackPointerTop)
            {
                // The first part of the argument is copied into the core registers starting at the NCRN up to and including r3.
                var sizedPassedInRegisters = 0;
                for (var r = ncrn; r < 4; r++)
                {
                    var rVal = unicorn.RegRead<uint>(Arm.Register.GetRegister(r));
                    MemoryMarshal.Write(target[targetIndex..], ref rVal);
                    targetIndex += 4;
                    sizedPassedInRegisters += 4;
                }

                // The remainder of the argument is copied onto the stack, starting at the NSAA.
                var onStackSize = inType.Size - sizedPassedInRegisters;
                unicorn.MemRead(nsaa, target[targetIndex..], (nuint)onStackSize);
                targetIndex += onStackSize;

                ncrn = 4;
                nsaa += (uint)onStackSize;

                continue;
            }

            // C.6
            ncrn = 4;

            // C.7
            if (inType.Alignment == 8)
                nsaa = CeilTo(nsaa, 8);

            // C.8
            unicorn.MemRead(nsaa, target[targetIndex..], (nuint)inType.Size);
            targetIndex += inType.Size;
            nsaa += (uint)inType.Size;
        }
    }

    public static int GetParametersSize(params AbiType[] adjustedParameterTypes)
    {
        return adjustedParameterTypes.Sum(p => p.Size);
    }

    public static T GetParameter<T>(ReadOnlySpan<byte> data, int index, params AbiType[] adjustedParameterTypes)
        where T : struct
    {
        var b = 0;
        for (var i = 0; i < index; i++)
        {
            b += adjustedParameterTypes[i].Size;
        }

        var slice = data[b..];
        var typed = MemoryMarshal.Cast<byte, T>(slice);

        return typed[0];
    }
}
