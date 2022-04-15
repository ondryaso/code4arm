namespace Code4Arm.Unicorn.Abstractions.Enums;

// uc_mode
[Flags]
public enum EngineMode
{
    LittleEndian = 0, // little-endian mode (default mode)
    BigEndian = 1 << 30, // big-endian mode

    // arm / arm64
    Arm = 0, // ARM mode
    Thumb = 1 << 4, // THUMB mode (including Thumb-2)

    // Deprecated, use UC_ARM_CPU_* with uc_ctl instead.
    MClass = 1 << 5, // ARM's Cortex-M series.
    V8 = 1 << 6, // ARMv8 A32 encodings for ARM
    ArmBE8 = 1 << 7, // Big-endian data and Little-endian code.
    // Legacy support for UC1 only.

    // arm (32bit) cpu types
    // Depreciated, use UC_ARM_CPU_* with uc_ctl instead.
    Arm926 = 1 << 7, // ARM926 CPU type
    Arm946 = 1 << 8, // ARM946 CPU type
    Arm1176 = 1 << 9, // ARM1176 CPU type

    // mips
    Micro = 1 << 4, // MicroMips mode (currently unsupported)
    Mips3 = 1 << 5, // Mips III ISA (currently unsupported)
    Mips32R6 = 1 << 6, // Mips32r6 ISA (currently unsupported)
    Mips32 = 1 << 2, // Mips32 ISA
    Mips64 = 1 << 3, // Mips64 ISA

    // x86 / x64
    Mode16Bit = 1 << 1, // 16-bit mode
    Mode32Bit = 1 << 2, // 32-bit mode
    Mode64Bit = 1 << 3, // 64-bit mode

    // ppc
    Ppc32 = 1 << 2, // 32-bit mode
    Ppc64 = 1 << 3, // 64-bit mode (currently unsupported)

    Qpx =
        1 << 4, // Quad Processing eXtensions mode (currently unsupported)

    // sparc
    Sparc32 = 1 << 2, // 32-bit mode
    Sparc64 = 1 << 3, // 64-bit mode
    V9 = 1 << 4, // SparcV9 mode (currently unsupported)

    // riscv
    RiscV32 = 1 << 2, // 32-bit mode
    RiscV64 = 1 << 3, // 64-bit mode
}