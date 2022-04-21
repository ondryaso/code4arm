// IOperandAnalyserProvider.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.CodeAnalysis.Models.Abstractions;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

public interface IOperandAnalyserProvider
{
    IOperandAnalyser For(IOperandDescriptor descriptor);
}
