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
        new InstructionVariant("ADD", true, true, true),
        new InstructionVariant("MOV", true, true, false),
        new InstructionVariant("NOP", false, true, false),
        new InstructionVariant("SB", false, false, false)
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
