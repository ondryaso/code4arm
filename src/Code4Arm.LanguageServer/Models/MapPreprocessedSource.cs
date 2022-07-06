// MapPreprocessedSource.cs
// Author: Ondřej Ondryáš

using System.Buffers;
using System.Text;
using Code4Arm.LanguageServer.Extensions;
using Code4Arm.LanguageServer.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.Models;

public class MapPreprocessedSource : BufferedSourceBase, IPreprocessorSource
{
    public IEnumerable<Range> Regions => Enumerable.Empty<Range>();
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

    public Task Preprocess(Range? modifiedRange)
    {
        var text = BaseSource.Text;

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

        if (_lastText.Length <= start || _lastText.Length <= end || start == -1 || end == -1)
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

            return new Range(s, s);
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
