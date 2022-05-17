// AbiTypes.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Environment;

public enum AbiTypeClass
{
    Integral = 1,
    Fp,
    Vector,
    Pointer
}

public enum AbiMachineType
{
    UnsignedByte = 1,
    SignedByte,
    UnsignedHalfWord,
    SignedHalfWord,
    UnsignedWord,
    SignedWord,
    UnsignedDoubleWord,
    SignedDoubleWord,
    HalfPrecision,
    SinglePrecision,
    DoublePrecision,
    Vector64,
    Vector128,
    DataPointer,
    CodePointer
}

public static class AbiMachineTypeExtensions
{
    public static bool IsSigned(this AbiMachineType type)
        => type is AbiMachineType.SignedByte or AbiMachineType.SignedWord or AbiMachineType.SignedDoubleWord
            or AbiMachineType.SignedDoubleWord;
}

public readonly record struct AbiType(AbiTypeClass Class, AbiMachineType MachineType, int Size, int Alignment)
{
    public AbiType(int size, int alignment) : this(0, 0, size, alignment)
    {
    }
}

public static class AbiTypes
{
    public static readonly AbiType UnsignedByte = new(AbiTypeClass.Integral, AbiMachineType.UnsignedByte, 1, 1);
    public static readonly AbiType SignedByte = new(AbiTypeClass.Integral, AbiMachineType.SignedByte, 1, 1);
    public static readonly AbiType UnsignedHalfWord = new(AbiTypeClass.Integral, AbiMachineType.UnsignedHalfWord, 2, 2);
    public static readonly AbiType SignedHalfWord = new(AbiTypeClass.Integral, AbiMachineType.SignedHalfWord, 2, 2);
    public static readonly AbiType UnsignedWord = new(AbiTypeClass.Integral, AbiMachineType.UnsignedWord, 4, 4);
    public static readonly AbiType SignedWord = new(AbiTypeClass.Integral, AbiMachineType.SignedWord, 4, 4);

    public static readonly AbiType UnsignedDoubleWord =
        new(AbiTypeClass.Integral, AbiMachineType.UnsignedDoubleWord, 8, 8);

    public static readonly AbiType SignedDoubleWord = new(AbiTypeClass.Integral, AbiMachineType.SignedDoubleWord, 8, 8);
    public static readonly AbiType HalfPrecision = new(AbiTypeClass.Fp, AbiMachineType.HalfPrecision, 2, 2);
    public static readonly AbiType SinglePrecision = new(AbiTypeClass.Fp, AbiMachineType.SinglePrecision, 4, 4);
    public static readonly AbiType DoublePrecision = new(AbiTypeClass.Fp, AbiMachineType.DoublePrecision, 8, 8);
    public static readonly AbiType Vector64 = new(AbiTypeClass.Vector, AbiMachineType.Vector64, 8, 8);
    public static readonly AbiType Vector128 = new(AbiTypeClass.Vector, AbiMachineType.Vector128, 16, 8);
    public static readonly AbiType DataPointer = new(AbiTypeClass.Pointer, AbiMachineType.DataPointer, 4, 4);
    public static readonly AbiType CodePointer = new(AbiTypeClass.Pointer, AbiMachineType.CodePointer, 4, 4);
}
