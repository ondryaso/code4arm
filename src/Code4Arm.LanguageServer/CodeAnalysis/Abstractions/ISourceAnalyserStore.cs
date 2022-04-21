// ISourceAnalyserStore.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.Models.Abstractions;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

public interface ISourceAnalyserStore
{
    ISourceAnalyser GetAnalyser(ISource source);
}
