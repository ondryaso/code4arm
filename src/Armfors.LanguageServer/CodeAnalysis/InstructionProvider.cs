// InstructionProvider.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;

namespace Armfors.LanguageServer.CodeAnalysis;

/// <summary>
/// Dummy implementation
/// </summary>
public class InstructionProvider : IInstructionProvider, IOperandAnalyserProvider, IInstructionValidatorProvider
{
    private List<InstructionVariant> instructions = new()
    {
        new InstructionVariant("ADD", true, true, false,
            new OperandDescriptor("(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register, true),
            new OperandDescriptor("(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register),
            new OperandDescriptor("#?([+-]?[0-9]+)", OperandType.ImmediateConstant, OperandTokenType.ImmediateConstant,
                false, 1)),

        new InstructionVariant("ADD", true, true, false,
            new OperandDescriptor("(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register, true),
            new OperandDescriptor("(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register),
            new OperandDescriptor("(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register),
            new OperandDescriptor(new[] { "(LSL|LSR|ASR|ROR)", " #?([0-9]+)" },
                OperandType.Shift, null, true, 0,
                (0, 1, new OperandToken(OperandTokenType.ShiftType)),
                (1, 1, new OperandToken(OperandTokenType.ImmediateShift)))),

        new InstructionVariant("MOV", true, true),
        new InstructionVariant("LDR", true, false, false,
            new OperandDescriptor("(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register),
            new OperandDescriptor(new[] { "\\[", "\\G ?(R0|R1|R2|R3|R4)", "\\G ?(, ?#?([+-]?[0-9]+))?", "\\G ?\\]" },
                OperandType.RegisterAddressing, null, false, 0,
                (1, 1, new OperandToken(OperandTokenType.Register)),
                (2, 2, new OperandToken(OperandTokenType.Immediate) { ImmediateSize = 4 })),
            new OperandDescriptor("(R0|R1|R2|R3|R4)", OperandType.Register, OperandTokenType.Register, true)),
        new InstructionVariant("B", true, true, false,
            new OperandDescriptor("(.+)", OperandType.Label, OperandTokenType.Label)),
        new InstructionVariant("NOP", false, false),
        new InstructionVariant("SB", false, false),
        new InstructionVariant("VADD", true, false, true)
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

    public IOperandAnalyser For(OperandDescriptor descriptor)
    {
        return new BasicOperandAnalyser(descriptor);
    }

    public IInstructionValidator? For(InstructionVariant instructionVariant)
    {
        return null;
    }
}
