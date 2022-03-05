// CustomSemanticTokenType.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer;

/// <summary>
/// Contains definitions of custom <see cref="SemanticTokenType"/> objects.
/// </summary>
public static class ArmSemanticTokenType
{
    /// An instruction mnemonic.
    public static readonly SemanticTokenType Instruction = new("instruction");

    /// An assembler directive.
    public static readonly SemanticTokenType Directive = new("directive");

    /// A register.
    public static readonly SemanticTokenType Register = new("register");

    /// A condition code appended to an instruction mnemonic.
    public static readonly SemanticTokenType ConditionCode = new("condition_code");

    /// A flag appended to an instruction mnemonic that controls if the instruction sets processor flags.
    public static readonly SemanticTokenType SetsFlagsFlag = new("sets_flags_flag");

    /// A vector data type flag.
    public static readonly SemanticTokenType VectorDataType = new("vector_data_type");
    
    /// An instruction size qualifier (.W/.N).
    public static readonly SemanticTokenType InstructionSizeQualifier = new("instruction_size_qualifier");
}

/// <summary>
/// Contains definitions of custom <see cref="SemanticTokenModifier"/> objects.
/// </summary>
public static class ArmSemanticTokenModifier
{
    // Marks an instruction that is executed conditionally.
    public static readonly SemanticTokenModifier Conditional = new("conditional");

    // Marks an instruction that controls if the instruction sets processor flags.
    public static readonly SemanticTokenModifier SetsFlags = new("sets_flags");

    // Marks a SIMD/FP instruction.
    public static readonly SemanticTokenModifier VectorInstruction = new("vector_instruction");

    public static IEnumerable<SemanticTokenModifier> All => new[]
    {
        Conditional, SetsFlags, VectorInstruction
    };
}
