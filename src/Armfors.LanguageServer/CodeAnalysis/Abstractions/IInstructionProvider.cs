// IInstructionProvider.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models;

namespace Armfors.LanguageServer.CodeAnalysis.Abstractions;

public interface IInstructionProvider
{
    Task<List<InstructionVariant>> GetAllInstructions();
    Task<List<InstructionVariant>> FindMatchingInstructions(string line);
}
