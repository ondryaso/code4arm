// ISourceAnalyserStore.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.Models.Abstractions;

namespace Armfors.LanguageServer.CodeAnalysis.Abstractions;

public interface ISourceAnalyserStore
{
    ISourceAnalyser GetAnalyser(ISource source);
}
