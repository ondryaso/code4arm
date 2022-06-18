// PreprocessedSource.cs
// Author: Ondřej Ondryáš

using System.Text.RegularExpressions;
using Code4Arm.LanguageServer.Extensions;
using Code4Arm.LanguageServer.Models.Abstractions;
using Microsoft.Extensions.Logging;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.Models;

public class PreprocessedSource : BufferedSourceBase, IPreprocessedSource
{
    internal PreprocessedSource(ISource baseSource, ILogger<PreprocessedSource> logger)
    {
        this.BaseSource = baseSource;
        _text = string.Empty;
    }

    // The negative look-ahead at the beginning stops this regex from matching *//* 
    private readonly Regex _singleLineCommentsRegex =
        new(@"(?:(?!\*)\/\/(?!\*)|@).*$", RegexOptions.Compiled | RegexOptions.Multiline);

    private readonly Regex _multiLineCommentsRegex = new(@"\/\*(?:.|\s)*?\*\/", RegexOptions.Compiled);
    private readonly Regex _multipleSpacesRegex = new(@"[ \t]{2,}", RegexOptions.Compiled);
    private readonly Regex _emptyLinesRegex = new(@"\n(?:\s*\n)+", RegexOptions.Compiled);


    private enum ReplacementType
    {
        OneLine,
        BlockComment,
        EmptyLines
    }

    private struct Replacement
    {
        public ReplacementType Type;
        public Range? FirstLineReplacedRange;
        public Range? LastLineReplacedRange;
        public int FirstLineIndex;
        public int LinesCut;

        public Replacement(Range replacedRange)
        {
            FirstLineReplacedRange = replacedRange;
            Type = ReplacementType.OneLine;
            FirstLineIndex = replacedRange.Start.Line;

            LastLineReplacedRange = null;
            LinesCut = 0;
        }

        public Replacement(Range firstLineRange, Range lastLineRange)
        {
            Type = ReplacementType.BlockComment;
            FirstLineReplacedRange = firstLineRange;
            LastLineReplacedRange = lastLineRange;
            FirstLineIndex = firstLineRange.Start.Line;
            LinesCut = lastLineRange.Start.Line - FirstLineIndex;
        }

        public Replacement(int firstLineIndex, int linesCut)
        {
            Type = ReplacementType.EmptyLines;
            FirstLineIndex = firstLineIndex;
            LinesCut = linesCut;

            FirstLineReplacedRange = LastLineReplacedRange = null;
        }
    }

    private readonly List<Replacement> _replacements = new();
    private readonly List<Range> _regions = new();

    private Range GetRangeForMatch(Match match, string? text = null)
    {
        text ??= _text;

        var startPosition = text.GetPositionForIndex(match.Index);
        var endPosition = text.GetPositionForIndex(match.Index + match.Length - 1);

        return new Range(startPosition, endPosition);
    }

    private void MakeRegions(ICollection<(Position Position, bool IsStart)> bounds)
    {
        _regions.Clear();
        var started = new List<Position>(4);

        foreach (var (pos, isStart) in bounds)
        {
            if (isStart)
            {
                started.Add(pos);
            }
            else
            {
                foreach (var s in started)
                {
                    _regions.Add(new Range(s, pos));
                }

                started.Clear();
            }
        }
    }

    internal Task Preprocess(Range? modifiedRange)
    {
        // TODO: Use ranges
        _replacements.Clear();

        // The order here is important
        _text = this.BaseSource.Text;

        var regionBounds = new List<(Position, bool)>();

        // Replace single-line comments with a single space.
        // There may only be one comment per line and the operation doesn't consume lines so determining all the ranges
        // on the original text is ok (unlike in the next steps).
        _text = _singleLineCommentsRegex.Replace(_text, match =>
        {
            var range = this.GetRangeForMatch(match);
            var val = match.ValueSpan[2..].TrimStart();

            if (val.StartsWith("#region", StringComparison.Ordinal))
                regionBounds.Add((range.Start, true));

            if (val.StartsWith("#endregion", StringComparison.Ordinal))
                regionBounds.Add((range.End, false));

            _replacements.Add(new Replacement(range));

            return " ";
        });

        this.MakeRegions(regionBounds);

        // Replace multi-line comments with a single space, take note of lines that have been shifted as a result.
        // The replacements are evaluated one-by-one so it's necessary to calculate them on the versions of text
        // resulting from their previous replacements.
        Match? lastMatch = null;
        while (true)
        {
            var newText = _multiLineCommentsRegex.Replace(_text, match =>
            {
                lastMatch = match;

                return " ";
            }, 1, (lastMatch?.Index + 1) ?? 0);

            if (lastMatch == null) break;
            if (newText == _text) break;

            var newLineIndex = lastMatch.Value.IndexOf('\n');
            if (newLineIndex == -1)
            {
                var firstLineRange = this.GetRangeForMatch(lastMatch);
                _replacements.Add(new Replacement(firstLineRange));
            }
            else
            {
                var firstLineRange = new Range(_text.GetPositionForIndex(lastMatch.Index),
                    _text.GetPositionForIndex(lastMatch.Index + newLineIndex));

                var endPosition = _text.GetPositionForIndex(lastMatch.Index + lastMatch.Length - 1);
                var lastLineRange = new Range(endPosition.Line, 0, endPosition.Line, endPosition.Character);
                _replacements.Add(new Replacement(firstLineRange, lastLineRange));
            }

            _text = newText;
        }

        // Replace multiple consecutive whitespaces with a single space
        _text = _multipleSpacesRegex.Replace(_text, match =>
        {
            _replacements.Add(new Replacement(this.GetRangeForMatch(match)));

            return " ";
        });

        // Get rid of all empty lines, take note of lines that have been shifted as a result
        lastMatch = null;
        while (true)
        {
            var newText = _emptyLinesRegex.Replace(_text, match =>
            {
                lastMatch = match;

                return "\n";
            }, 1, (lastMatch?.Index + 1) ?? 0);

            if (lastMatch == null) break;
            if (newText == _text) break;

            var position = _text.GetPositionForIndex(lastMatch.Index);

            var replacement = new Replacement(position.Line, lastMatch.Value.Count(a => a == '\n') - 1);
            _replacements.Add(replacement);

            _text = newText;
        }

        return Task.CompletedTask;
    }

    public override bool IsValidRepresentation => this.BaseSource.IsValidRepresentation;

    public override DocumentUri Uri => this.BaseSource.Uri;

    public override int? Version => this.BaseSource.Version;

    private string _text;

    public override string Text
    {
        get => _text;
        internal set =>
            throw new InvalidOperationException("Text must be set on the base source and preprocessed after.");
    }

    public ISource BaseSource { get; }

    public Range GetOriginalRange(Range preprocessedRange)
    {
        var startPos = new Position(preprocessedRange.Start.Line, preprocessedRange.Start.Character);
        var endPos = new Position(preprocessedRange.End.Line, preprocessedRange.End.Character);

        foreach (var replacement in Enumerable.Reverse(_replacements))
        {
            if (replacement.Type == ReplacementType.OneLine)
            {
                if (replacement.FirstLineReplacedRange == null)
                    throw new Exception();

                // PrepRange starts on the line with replacement, after the replacement
                // -> shift it to the right
                if (replacement.FirstLineIndex == startPos.Line &&
                    startPos.Character > replacement.FirstLineReplacedRange.Start.Character)
                {
                    var offset = replacement.FirstLineReplacedRange.End.Character -
                        replacement.FirstLineReplacedRange.Start.Character;

                    startPos.Character += offset;
                }

                if (replacement.FirstLineIndex == endPos.Line &&
                    endPos.Character > replacement.FirstLineReplacedRange.Start.Character)
                {
                    var offset = replacement.FirstLineReplacedRange.End.Character -
                        replacement.FirstLineReplacedRange.Start.Character;

                    endPos.Character += offset;
                }
            }

            if (replacement.Type == ReplacementType.EmptyLines)
            {
                if (startPos.Line > replacement.FirstLineIndex)
                {
                    startPos.Line += replacement.LinesCut;
                }

                if (endPos.Line > replacement.FirstLineIndex)
                {
                    endPos.Line += replacement.LinesCut;
                }
            }

            if (replacement.Type == ReplacementType.BlockComment)
            {
                if (replacement.FirstLineReplacedRange == null || replacement.LastLineReplacedRange == null)
                    throw new Exception();

                if (replacement.FirstLineIndex == startPos.Line &&
                    startPos.Character > replacement.FirstLineReplacedRange.Start.Character)
                {
                    var offset = startPos.Character - replacement.FirstLineReplacedRange.Start.Character;
                    startPos.CopyFrom(replacement.LastLineReplacedRange.End);
                    startPos.Character += offset;
                }

                if (replacement.FirstLineIndex == endPos.Line &&
                    endPos.Character >= replacement.FirstLineReplacedRange.Start.Character)
                {
                    var offset = endPos.Character - replacement.FirstLineReplacedRange.Start.Character;
                    endPos.CopyFrom(replacement.LastLineReplacedRange.End);
                    endPos.Character += offset;
                }
            }
        }

        return new Range(startPos, endPos);
    }

    public Range GetPreprocessedRange(Range originalRange)
    {
        var startPos = new Position(originalRange.Start.Line, originalRange.Start.Character);
        var endPos = new Position(originalRange.End.Line, originalRange.End.Character);

        foreach (var replacement in _replacements)
        {
            if (replacement.Type is ReplacementType.BlockComment or ReplacementType.OneLine)
            {
                if (replacement.FirstLineReplacedRange == null)
                    throw new Exception();

                if (replacement.FirstLineReplacedRange.Contains(startPos))
                {
                    startPos.CopyFrom(replacement.FirstLineReplacedRange.Start);
                }

                if (replacement.FirstLineReplacedRange.Contains(endPos))
                {
                    endPos.CopyFrom(replacement.FirstLineReplacedRange.Start);
                }
                else if (replacement.FirstLineIndex == endPos.Line &&
                         endPos.Character > replacement.FirstLineReplacedRange.End.Character)
                {
                    endPos.Character -= replacement.FirstLineReplacedRange.End.Character -
                        replacement.FirstLineReplacedRange.Start.Character;
                }
            }

            if (replacement.Type == ReplacementType.BlockComment)
            {
                if (replacement.LastLineReplacedRange == null || replacement.FirstLineReplacedRange == null)
                    throw new Exception();

                if (replacement.LastLineReplacedRange.Contains(startPos))
                {
                    startPos.CopyFrom(replacement.LastLineReplacedRange.End);
                }

                if (replacement.LastLineReplacedRange.Contains(endPos))
                {
                    endPos.CopyFrom(replacement.LastLineReplacedRange.End);
                }
                else if (replacement.LastLineReplacedRange.End.Line == endPos.Line)
                {
                    endPos.Character = replacement.FirstLineReplacedRange.Start.Character
                        + (endPos.Character - replacement.LastLineReplacedRange.End.Character);
                }
            }

            if (replacement.Type is ReplacementType.BlockComment or ReplacementType.EmptyLines)
            {
                // TODO: Nestačí to tady jen odečíst, nefunguje, pokud je zdrojová pozice uvnitř té smazané části
                // řešení: ukládat celý smazaný range a nějak to spočítat? 

                if (startPos.Line > replacement.FirstLineIndex)
                {
                    startPos.Line -= replacement.LinesCut;
                }

                if (endPos.Line > replacement.FirstLineIndex)
                {
                    endPos.Line -= replacement.LinesCut;
                }
            }
        }

        return new Range(startPos, endPos);
    }

    public IEnumerable<Range> Regions => _regions;
}
