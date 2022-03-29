using Armfors.LanguageServer.CodeAnalysis.Models;

namespace Armfors.LanguageServer.CodeAnalysis.Abstractions;

public interface IDirectiveAnalyser
{
    AnalysedDirective AnalyseDirective(string directiveText, int directiveStartLinePosition,
        int lineIndex);
}