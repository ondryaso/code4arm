// AnalysedLabel.cs
// Author: Ondřej Ondryáš

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

public record AnalysedLabel(string Label, Range Range, AnalysedLine? PointsTo, AnalysedLabel? Redefines = null,
    bool CanBeRedefined = false);
