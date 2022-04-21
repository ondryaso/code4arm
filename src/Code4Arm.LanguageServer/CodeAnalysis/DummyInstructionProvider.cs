// DummyInstructionProvider.cs
// Author: Ondřej Ondryáš

#if false
using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using Code4Arm.LanguageServer.CodeAnalysis.Models;

namespace Code4Arm.LanguageServer.CodeAnalysis;

/// <summary>
/// Dummy implementation
/// </summary>
public class DummyInstructionProvider : IInstructionProvider, IOperandAnalyserProvider, IInstructionValidatorProvider
{
    private List<InstructionVariant> instructions = new()
    {
        new InstructionVariant("ADD", true, true, false,
            new OperandDescriptor("(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register, "<Rd>", 1, true),
            new OperandDescriptor("\\G(SP)", OperandType.Register, false,
                (0, 1, new OperandToken(OperandTokenType.Register, "SP") {RegisterMask = Register.SP})),
            new OperandDescriptor("\\G#?([+-]?[0-9]+)", OperandType.ImmediateConstant,
                OperandTokenType.ImmediateConstant,
                "<const>")) {VariantPriority = 0, VariantFlags = InstructionVariantFlag.UncommonVariant},

        new InstructionVariant("ADD", true, true, false,
            new OperandDescriptor("(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register, "<Rd>", 1, true),
            new OperandDescriptor("\\G(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register, "<Rn>"),
            new OperandDescriptor("\\G#?([+-]?[0-9]+)", OperandType.ImmediateConstant,
                OperandTokenType.ImmediateConstant,
                "<const>")) {VariantPriority = 1},

        new InstructionVariant("ADD", true, true, false,
                new OperandDescriptor("(R15|R0|R1|R2|R3|R4|PC)", OperandType.Register, OperandTokenType.Register,
                    "<Rd>"),
                new OperandDescriptor("\\G(R15|R0|R1|R2|R3|R4|PC)", OperandType.Register, OperandTokenType.Register,
                    "<Rn>"),
                new OperandDescriptor("\\G(R15|R0|R1|R2|R3|R4|PC)", OperandType.Register, OperandTokenType.Register,
                    "<Rm>"),
                new OperandDescriptor(new[] {"\\G(LSL|LSR|ASR|ROR)", "\\G #?([0-9]+)"},
                    OperandType.Shift, true,
                    (0, 1, new OperandToken(OperandTokenType.ShiftType, "<shift>")),
                    (1, 1, new OperandToken(OperandTokenType.ImmediateShift, "<imm>"))))
            {VariantPriority = 2},

        new InstructionVariant("MOV", true, true),
/*
        new InstructionVariant("LDR", true, false, false,
            new OperandDescriptor("(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register, "<Rd>"),
            new OperandDescriptor(new[] { "\\[", "\\G ?(R0|R1|R2|R3|R4)", "\\G ?(, ?#?([+-]?[0-9]+))?", "\\G ?\\]" },
                OperandType.ImmediateAddressing, false, (1, 1, new OperandToken(OperandTokenType.Register, "<Rn>")),
                (2, 2, new OperandToken(OperandTokenType.Immediate, "<imm>") { ImmediateSize = 4 })),
            new OperandDescriptor("(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register, "<Rx>", 1,
                true)),*/

        new InstructionVariant("LDR", true, false, false,
            new OperandDescriptor("(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register, "<Rd>"),
            new OperandDescriptor(new[] {"\\[", "\\G ?(R0|R1|R2|R3|R4)", "\\G ?, ?(R0|R1|R2|R3|R4)", " ?\\]"},
                OperandType.RegisterAddressing, false,
                (1, 1, new OperandToken(OperandTokenType.Register, "<Rn>")),
                (2, 1, new OperandToken(OperandTokenType.Register, "<Rm>"))),
            new OperandDescriptor("\\G(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register, "<Rx>")),

        new InstructionVariant("B", true, true, false,
            new OperandDescriptor("\\G(.+)", OperandType.Label, OperandTokenType.Label, "<label>")),

        new InstructionVariant("BX", true, false, false,
            new OperandDescriptor("\\G(R14|R0|R1|LR)", OperandType.Register, false,
                (0, 1,
                    new OperandToken(OperandTokenType.Register, "<Rs>")
                        {RegisterMask = Register.R0 | Register.R1 | Register.LR}))),

        new InstructionVariant("NOP", false, false),
        new InstructionVariant("SB", false, false) {VariantFlags = InstructionVariantFlag.AdvancedInstruction},
        new InstructionVariant("VADD", true, false, true) {VariantFlags = InstructionVariantFlag.Simd}
    };

    public Task<List<InstructionVariant>> GetAllInstructions()
    {
        return Task.FromResult(instructions);
    }

    public Task<List<InstructionVariant>> FindMatchingInstructions(string line)
    {
        return Task.FromResult(instructions
            .Where(m => m.Mnemonic.StartsWith(line, StringComparison.InvariantCultureIgnoreCase)).ToList());
    }

    public Task<List<InstructionVariant>> GetVariants(string mnemonic, InstructionVariantFlag exclude)
    {
        return Task.FromResult(instructions
            .Where(m => m.Mnemonic.Equals(mnemonic, StringComparison.InvariantCultureIgnoreCase))
            .Where(m => (m.VariantFlags & exclude) == 0)
            .ToList());
    }

    public IOperandAnalyser For(OperandDescriptor descriptor)
    {
        return new BasicOperandAnalyser(descriptor);
    }

    public IInstructionValidator? For(InstructionVariant instructionVariant)
    {
        return null;
    }
}
#endif