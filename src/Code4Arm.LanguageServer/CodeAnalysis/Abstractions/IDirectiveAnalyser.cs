using Code4Arm.LanguageServer.CodeAnalysis.Models;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

public interface IDirectiveAnalyser
{
    AnalysedDirective AnalyseDirective(string directiveText, int directiveStartLinePosition,
        ISourceAnalyser sourceAnalyser);
}