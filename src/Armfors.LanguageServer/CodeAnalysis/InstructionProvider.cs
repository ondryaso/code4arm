// InstructionProvider.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;

namespace Armfors.LanguageServer.CodeAnalysis;

/// <summary>
/// Dummy implementation
/// </summary>
public class InstructionProvider : IInstructionProvider
{
    private List<InstructionVariant> instructions = new()
    {
        new InstructionVariant("ADD", true, true, false,
            new OperandDescriptor("abc", OperandType.Register, OperandTokenType.Register),
            new OperandDescriptor("efg", OperandType.Label, OperandTokenType.Label, true),
            new OperandDescriptor("hij", OperandType.ShiftType, OperandTokenType.ShiftType)),

        new InstructionVariant("MOV", true, true),
        new InstructionVariant("LDR", true, false),
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
}
