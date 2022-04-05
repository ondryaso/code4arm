namespace Armfors.LanguageServer.CodeAnalysis.Models;

internal class AnalysisContext
{
    public AnalysisContext(SourceAnalyser sourceAnalyser, int startingLinesCapacity, int startingLabelsCapacity)
    {
        this.Analyser = sourceAnalyser;
        this.AnalysedLines = new Dictionary<int, AnalysedLine>(startingLinesCapacity);
        this.AnalysedLabels = new Dictionary<string, AnalysedLabel>(startingLabelsCapacity);
        this.StubLabels = new List<AnalysedLabel>(startingLabelsCapacity);
    }

    public SourceAnalyser Analyser { get; }

    public AnalysedLine CurrentLine { get; set; } = new(0, 0) { State = LineAnalysisState.Blank };
    public string CurrentLineText { get; set; } = string.Empty;
    public int CurrentLineIndex { get; set; } = -1;

    public Dictionary<int, AnalysedLine> AnalysedLines { get; }
    public Dictionary<string, AnalysedLabel> AnalysedLabels { get; }
    public List<AnalysedLabel> StubLabels { get; }
    public List<AnalysedFunction>? StubFunctions { get; set; }
    public List<string>? GlobalLabels { get; set; }
    public bool FirstRunOnCurrentLine { get; set; } = true;
    public bool InsideString { get; set; } = false;

    public LineAnalysisState State { get; set; } = LineAnalysisState.Empty;
}
