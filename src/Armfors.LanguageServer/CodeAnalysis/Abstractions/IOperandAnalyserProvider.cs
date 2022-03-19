// IOperandAnalyserProvider.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models;

namespace Armfors.LanguageServer.CodeAnalysis.Abstractions;

public interface IOperandAnalyserProvider
{
    IOperandAnalyser For(OperandDescriptor descriptor);
}
