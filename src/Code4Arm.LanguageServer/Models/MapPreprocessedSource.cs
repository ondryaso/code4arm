// MapPreprocessedSource.cs
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

using System.Buffers;
using System.Text;
using Code4Arm.LanguageServer.Extensions;
using Code4Arm.LanguageServer.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.Models;

public class MapPreprocessedSource : BufferedSourceBase, IPreprocessorSource
{
    public IEnumerable<Range> Regions => _regions;

    public IReadOnlyList<int> SuppressedLines => _suppressedLines;
    public IReadOnlyList<int> IgnoredLines => _ignoredLines;

    public record struct SpaceInfo(int Left, int Right);

    private Dictionary<int, SpaceInfo> _spaceInfos = new();

    public override string Text
    {
        get => _lastText;
        internal set =>
            throw new InvalidOperationException("Text must be set on the base source and preprocessed after.");
    }

    // private object _analyserLock = new();
    private string? _lastInputText;
    private string _lastText = string.Empty;
    private int[]? _sourceToPreprocessed;
    private int[]? _preprocessedToSource;
    private readonly ArrayPool<int> _arrayPool;

    private enum BoundType
    {
        Region,
        Suppressed,
        Ignored
    }

    private readonly List<(Position Position, bool IsStart, BoundType Type)> _regionBounds = new();
    private readonly List<Range> _regions = new();
    private List<int> _suppressedLines = new();
    private List<int> _ignoredLines = new();

    public MapPreprocessedSource(ISource baseSource)
    {
        BaseSource = baseSource;
        _arrayPool = ArrayPool<int>.Shared;
    }

    private enum State
    {
        Start,
        Text,
        Space,
        CommentStart,
        CommentSingle,
        CommentMulti,
        PossibleMultiEnd,
    }

    private void MakeRegions()
    {
        _regions.Clear();
        var started = new Stack<Position>(4);

        foreach (var (pos, isStart, type) in _regionBounds)
        {
            if (type != BoundType.Region)
                continue;

            if (isStart)
            {
                started.Push(pos);
            }
            else
            {
                if (started.Count == 0)
                    continue;
                
                _regions.Add(new Range(started.Pop(), pos));
            }
        }

        if (started.Count > 0 && _lastInputText != null)
        {
            var endPos = _lastInputText.GetPositionForIndex(_lastInputText.Length - 1);
            foreach (var start in started)
            {
                _regions.Add(new Range(start, endPos));
            }
            
            started.Clear();
        }
    }

    private void MakeSuppressedOrIgnoredLines(BoundType type, ref List<int> target)
    {
        if (type == BoundType.Region) return;

        var started = new List<int>(4);

        foreach (var (pos, isStart, regType) in _regionBounds)
        {
            if (regType != type)
                continue;

            if (isStart)
            {
                started.Add(pos.Line);
            }
            else
            {
                foreach (var s in started)
                {
                    for (var i = s; i < pos.Line; i++)
                    {
                        target.Add(i);
                    }
                }

                started.Clear();
            }
        }

        if (started.Count != 0)
        {
            var smallest = started.Min();
            var endLine = _lastInputText!.GetPositionForIndex(_lastInputText!.Length - 1).Line;
            for (var i = smallest; i <= endLine; i++)
            {
                target.Add(i);
            }
        }

        target = target.Distinct().ToList();
        target.Sort();
    }

    private void CheckMetaKeywords(string text, int commentIndex)
    {
        if (commentIndex >= text.Length)
            return;

        // Ignore whitespaces
        while (char.IsWhiteSpace(text[commentIndex]))
        {
            if (text[commentIndex] == '\n')
                return;

            commentIndex++;

            if (commentIndex == text.Length)
                return;
        }

        if (text[commentIndex] != '#')
            return;

        var position = text.GetPositionForIndex(commentIndex);

        if (text.IndexOf("#region", commentIndex, StringComparison.Ordinal) == commentIndex)
        {
            _regionBounds.Add((position, true, BoundType.Region));
        }
        else if (text.IndexOf("#endregion", commentIndex, StringComparison.Ordinal) == commentIndex)
        {
            _regionBounds.Add((position, false, BoundType.Region));
        }

        if (text.IndexOf("#suppress", commentIndex, StringComparison.Ordinal) == commentIndex)
        {
            _regionBounds.Add((position, true, BoundType.Suppressed));
        }
        else if (text.IndexOf("#endsuppress", commentIndex, StringComparison.Ordinal) == commentIndex)
        {
            _regionBounds.Add((position, false, BoundType.Suppressed));
        }

        if (text.IndexOf("#ignore", commentIndex, StringComparison.Ordinal) == commentIndex)
        {
            _regionBounds.Add((position, true, BoundType.Ignored));
        }
        else if (text.IndexOf("#endignore", commentIndex, StringComparison.Ordinal) == commentIndex)
        {
            _regionBounds.Add((position, false, BoundType.Ignored));
        }
        else if (text.IndexOf("#!", commentIndex, StringComparison.Ordinal) == commentIndex)
        {
            if (text.Length > (commentIndex + 2) && text[commentIndex + 2] == '!')
            {
                // comment begins with #!!
                _ignoredLines.Add(position.Line);
            }
            else
            {
                _suppressedLines.Add(position.Line);
            }
        }
    }

    public Task Preprocess(Range? modifiedRange)
    {
        var text = BaseSource.Text;

        _regionBounds.Clear();
        _suppressedLines.Clear();
        _ignoredLines.Clear();

        var sourceToPreprocessed = _arrayPool.Rent(text.Length);
        var preprocessedToSource = _arrayPool.Rent(text.Length + 1);
        var spaceInfos = new Dictionary<int, SpaceInfo>();

        // si: index in source text, pi: index in preprocessed text

        var pi = -1;
        var sb = new StringBuilder(text.Length);
        var state = State.Start;
        var commentBeganIn = State.Start;

        for (var si = 0; si < text.Length; si++)
        {
            var c = text[si];
            switch (state)
            {
                case State.Start:
                    if (c == '\n')
                    {
                        sb.Append(c);
                        MapFrom(si, ++pi);
                        MapTo(si, pi);
                    }
                    else if (c == '/')
                    {
                        state = State.CommentStart;
                        MapTo(si, pi == -1 ? 0 : pi);
                    }
                    else if (c == '@')
                    {
                        state = State.CommentSingle;
                        MapTo(si, pi == -1 ? 0 : pi);
                        this.CheckMetaKeywords(text, si + 1);
                    }
                    else if (c != ' ')
                    {
                        MapFrom(si, ++pi);
                        MapTo(si, pi);

                        sb.Append(c);
                        state = State.Text;
                    }
                    else
                    {
                        MapTo(si, pi == -1 ? 0 : pi);
                    }

                    break;

                case State.Text:
                    if (c == ' ')
                    {
                        state = State.Space;
                        MapSpaceBegin(si, pi + 1);
                        MapFrom(si, pi + 1);
                        MapTo(si, pi + 1);
                    }
                    else if (c == '/')
                    {
                        commentBeganIn = State.Text;
                        state = State.CommentStart;
                        MapSpaceBegin(si, pi + 1);
                        MapFrom(si, pi + 1);
                        MapTo(si, pi + 1);
                    }
                    else if (c == '@')
                    {
                        commentBeganIn = State.Text;
                        state = State.CommentSingle;
                        MapSpaceBegin(si, pi + 1);
                        MapFrom(si, pi + 1);
                        MapTo(si, pi + 1);

                        this.CheckMetaKeywords(text, si + 1);
                    }
                    else
                    {
                        MapFrom(si, ++pi);
                        MapTo(si, pi);
                        sb.Append(c);
                    }

                    break;
                case State.Space:
                    if (c == '/')
                    {
                        commentBeganIn = State.Space;
                        state = State.CommentStart;
                        MapTo(si, pi + 1);
                    }
                    else if (c == '@')
                    {
                        commentBeganIn = State.Space;
                        state = State.CommentSingle;
                        MapTo(si, pi + 1);
                        this.CheckMetaKeywords(text, si + 1);
                    }
                    else if (c == '\n')
                    {
                        MapSpaceEnd(si, ++pi);
                        MapTo(si, pi);
                        sb.Append('\n');

                        state = State.Text;
                    }
                    else if (c != ' ')
                    {
                        MapSpaceEnd(si - 1, ++pi);
                        MapTo(si - 1, pi);
                        sb.Append(' ');

                        MapFrom(si, ++pi);
                        MapTo(si, pi);
                        sb.Append(c);
                        state = State.Text;
                    }
                    else
                    {
                        MapTo(si, pi + 1);
                    }

                    break;
                case State.CommentStart:
                    if (c == '/')
                    {
                        state = State.CommentSingle;
                        MapTo(si, pi + 1);
                        this.CheckMetaKeywords(text, si + 1);
                    }
                    else if (c == '*')
                    {
                        state = State.CommentMulti;
                        MapTo(si, pi + 1);
                    }
                    else
                    {
                        if (commentBeganIn == State.Space)
                        {
                            MapSpaceEnd(si - 2, ++pi);
                            MapTo(si - 2, pi);
                            sb.Append(' ');
                        }

                        MapFrom(si - 1, ++pi);
                        MapTo(si - 1, pi);
                        MapFrom(si, ++pi);
                        MapTo(si, pi);

                        sb.Append('/');
                        sb.Append(c);

                        state = State.Text;
                    }

                    break;
                case State.CommentSingle:
                    MapTo(si, pi + 1);

                    if (c == '\n')
                    {
                        MapSpaceEnd(si, ++pi);
                        sb.Append(c);
                        state = commentBeganIn == State.Start ? State.Start : State.Text;
                    }

                    break;
                case State.CommentMulti:
                    if (c == '*')
                    {
                        state = State.PossibleMultiEnd;
                    }

                    MapTo(si, pi + 1);

                    break;
                case State.PossibleMultiEnd:
                    if (c == '/')
                    {
                        state = commentBeganIn == State.Text ? State.Space : commentBeganIn;
                    }
                    else if (c != '*')
                    {
                        state = State.CommentMulti;
                    }

                    MapTo(si, pi + 1);

                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        if (_sourceToPreprocessed != null)
            _arrayPool.Return(_sourceToPreprocessed);
        if (_preprocessedToSource != null)
            _arrayPool.Return(_preprocessedToSource);

        _lastInputText = text;
        _lastText = sb.ToString();
        _sourceToPreprocessed = sourceToPreprocessed;
        _preprocessedToSource = preprocessedToSource;
        _spaceInfos = spaceInfos;
        this.MakeRegions();
        this.MakeSuppressedOrIgnoredLines(BoundType.Ignored, ref _ignoredLines);
        this.MakeSuppressedOrIgnoredLines(BoundType.Suppressed, ref _suppressedLines);

        return Task.CompletedTask;

        void MapFrom(int sourceIndex, int preprocessedIndex)
        {
            preprocessedToSource![preprocessedIndex] = sourceIndex;
        }

        void MapTo(int sourceIndex, int preprocessedIndex)
        {
            sourceToPreprocessed![sourceIndex] = preprocessedIndex;
        }

        void MapSpaceBegin(int sourceIndex, int preprocessedIndex)
        {
            // if (spaceInfos.ContainsKey(preprocessedIndex)) return;
            spaceInfos!.Add(preprocessedIndex, new SpaceInfo(sourceIndex, sourceIndex));
        }

        void MapSpaceEnd(int sourceIndex, int preprocessedIndex)
        {
            if (!spaceInfos.TryGetValue(preprocessedIndex, out var current)) return;
            spaceInfos![preprocessedIndex] = current with { Right = sourceIndex };
        }
    }

    public Range GetOriginalRange(Range preprocessedRange)
    {
        if (this is { _preprocessedToSource: null } or { _lastInputText: null })
            throw new InvalidOperationException("The text is not preprocessed yet.");

        var start = _lastText.GetIndexForPosition(preprocessedRange.Start);
        var end = _lastText.GetIndexForPosition(preprocessedRange.End);
        var isExpectedEnd = false;
        if (end == -1)
        {
            end = start;
            isExpectedEnd = true;
        } 

        if (start >= _lastText.Length) start = _lastText.Length - 1;
        if (end >= _lastText.Length) end = _lastText.Length - 1;

        if (start == -1 || end == -1)
            throw new InvalidOperationException("Invalid range.");
        
        if (start == (end - 1) && _spaceInfos.TryGetValue(start, out var startSpace))
        {
            return new Range(_lastInputText.GetPositionForIndex(startSpace.Left),
                _lastInputText.GetPositionForIndex(startSpace.Right + 1));
        }

        var startIndex = _spaceInfos.TryGetValue(start, out startSpace)
            ? startSpace.Right
            : _preprocessedToSource[start];

        if (start == end)
        {
            var s = _lastInputText.GetPositionForIndex(startIndex);

            if (isExpectedEnd)
            {
                return new Range(s, new Position(s.Line, s.Character + (preprocessedRange.End.Character - preprocessedRange.Start.Character)));
            }
            else
            {
                return new Range(s, s);
            }
        }

        var endIndex = _spaceInfos.TryGetValue(end - 1, out var endSpace)
            ? (endSpace.Left + 1)
            : _preprocessedToSource[end];

        return new Range(_lastInputText.GetPositionForIndex(startIndex),
            _lastInputText.GetPositionForIndex(endIndex));
    }

    public Range GetPreprocessedRange(Range originalRange)
    {
        if (this is { _sourceToPreprocessed: null } or { _lastText: null } or { _lastInputText: null })
            throw new InvalidOperationException("The text is not preprocessed yet.");

        var start = _lastInputText.GetIndexForPosition(originalRange.Start);
        var end = _lastInputText.GetIndexForPosition(originalRange.End);

        if (_sourceToPreprocessed.Length <= start || _sourceToPreprocessed.Length <= end)
            throw new InvalidOperationException("Invalid range.");

        var startIndex = _sourceToPreprocessed[start];
        var endIndex = _sourceToPreprocessed[end];

        return new Range(_lastText.GetPositionForIndex(startIndex), _lastText.GetPositionForIndex(endIndex));
    }

    public override bool IsValidRepresentation => BaseSource.IsValidRepresentation;
    public override DocumentUri Uri => BaseSource.Uri;
    public override int? Version => BaseSource.Version;
    public ISource BaseSource { get; }
}
