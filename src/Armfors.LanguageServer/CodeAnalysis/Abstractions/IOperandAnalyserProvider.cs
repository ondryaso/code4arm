// IOperandAnalyserProvider.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models.Abstractions;

namespace Armfors.LanguageServer.CodeAnalysis.Abstractions;

public interface IOperandAnalyserProvider
{
    IOperandAnalyser For(IOperandDescriptor descriptor);
}
