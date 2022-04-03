// InstructionVariantFlag.cs
// Author: Ondřej Ondryáš

namespace Armfors.LanguageServer.CodeAnalysis.Models;

[Flags]
public enum InstructionVariantFlag
{
    /// <summary>
    /// The instruction variant has no special usage flags.
    /// </summary>
    NoFlags = 0,
    /// <summary>
    /// The instruction is a SIMD/FP instruction.
    /// </summary>
    Simd = 1 << 0,
    /// <summary>
    /// The instruction is uncommon – students should learn about them but not right at the beginning.
    /// This includes some less used ALU operations like saturating add.
    /// </summary>
    UncommonInstruction = 1 << 1,
    /// <summary>
    /// The instruction is advanced – Arm beginner students are not expected to use them.
    /// </summary>
    AdvancedInstruction = 1 << 2,
    /// <summary>
    /// Other variants of the instruction may not be flagged but this one is not a common one. 
    /// </summary>
    UncommonVariant = 1 << 3
}
