// AnalysedFunction.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

public class AnalysedFunction
{
    public AnalysedFunction(string label, AnalysedDirective typeDirective)
    {
        this.Label = label;
        this.TypeDirective = typeDirective;
    }

    public string Label { get; }
    public AnalysedDirective TypeDirective { get; }
    public AnalysedLabel? TargetAnalysedLabel { get; set; }
    public int StartLine { get; set; } = -1;
    public int EndLine { get; set; } = -1;
}
