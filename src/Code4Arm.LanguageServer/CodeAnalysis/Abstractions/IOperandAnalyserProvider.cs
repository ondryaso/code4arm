// IOperandAnalyserProvider.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.CodeAnalysis.Models.Abstractions;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

/// <summary>
/// Provides <see cref="IOperandAnalyser"/> instances for <see cref="IOperandDescriptor"/> objects.
/// </summary>
public interface IOperandAnalyserProvider
{
    /// <summary>
    /// Create an <see cref="IOperandAnalyser"/> instance for a given operand descriptor.
    /// </summary>
    IOperandAnalyser For(IOperandDescriptor descriptor);
}
