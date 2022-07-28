// AnalysisContext.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

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
