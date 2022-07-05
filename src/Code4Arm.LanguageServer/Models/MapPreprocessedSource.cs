// MapPreprocessedSource.cs
// Author: Ondřej Ondryáš

using System.Buffers;
using System.Text;
using Code4Arm.LanguageServer.Extensions;
using Code4Arm.LanguageServer.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.Models;

public class MapPreprocessedSource : BufferedSourceBase, IPreprocessedSource
{
    public IEnumerable<Range> Regions => Enumerable.Empty<Range>();

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
        Space,
        NewLine,
        PossibleComment,
        CommentSingle,
        CommentMulti,
        PossibleMultiEnd,
    }

    internal Task Preprocess(Range? modifiedRange)
    {
        var text = BaseSource.Text;

        var sourceToPreprocessed = _arrayPool.Rent(text.Length);
        var preprocessedToSource = _arrayPool.Rent(text.Length + 1);

        // si: index in source text, pi: index in preprocessed text

        var pi = -1;
        var sb = new StringBuilder(text.Length);
        var state = State.Start;
        var textStarted = false;

        for (var si = 0; si < text.Length; si++)
        {
            var c = text[si];
            switch (state)
            {
                case State.Start:
                    if (char.IsWhiteSpace(c) && c is not '\n')
                    {
                        state = State.Space;
                        textStarted = false;
                    }
                    else if (c == '@')
                    {
                        state = State.CommentSingle;
                        textStarted = false;
                    }
                    else if (c == '/')
                    {
                        state = State.PossibleComment;
                        textStarted = false;
                    }
                    else if (c is not '\n')
                    {
                        textStarted = true;
                    }
                    else
                    {
                        state = State.NewLine;
                    }

                    if (textStarted)
                    {
                        sb.Append(c);
                        pi++;
                    }

                    break;
                case State.Space:
                    if (c != ' ')
                    {
                        state = State.Start;
                        si--;
                        textStarted = false;

                        if (c != '\n')
                        {
                            sb.Append(' ');
                            pi++;
                        }
                        continue;
                    }

                    break;
                case State.NewLine:
                    if (!char.IsWhiteSpace(c))
                    {
                        state = State.Start;
                        si--;
                        textStarted = false;

                        continue;
                    }

                    break;
                case State.PossibleComment:
                    if (c == '/')
                    {
                        state = State.CommentSingle;
                    }
                    else if (c == '*')
                    {
                        state = State.CommentMulti;
                    }
                    else
                    {
                        state = State.Start;
                        si--;

                        continue;
                    }

                    break;
                case State.CommentSingle:
                    if (c is '\n')
                    {
                        state = State.NewLine;
                        sb.Append(c);
                        pi++;
                        textStarted = false;
                    }

                    break;
                case State.CommentMulti:
                    if (c == '*')
                    {
                        state = State.PossibleMultiEnd;
                    }

                    break;
                case State.PossibleMultiEnd:
                    if (c == '/')
                    {
                        state = State.Start;
                        textStarted = false;

                        if (si != text.Length - 1 && text[si + 1] != '\n')
                        {
                            sb.Append(' ');
                            pi++;
                        }
                    }
                    else
                    {
                        state = State.CommentMulti;
                        si--;

                        continue;
                    }

                    break;
                default:
                    throw new Exception();
            }

            if (pi != -1)
            {
                sourceToPreprocessed[si] = pi;
                preprocessedToSource[pi] = si;
            }
            else
            {
                sourceToPreprocessed[si] = 0;
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

        return Task.CompletedTask;
    }

    public Range GetOriginalRange(Range preprocessedRange)
    {
        if (this is { _preprocessedToSource: null } or { _lastInputText: null })
            throw new InvalidOperationException("The text is not preprocessed yet.");

        var start = _lastText.GetIndexForPosition(preprocessedRange.Start);
        var end = _lastText.GetIndexForPosition(preprocessedRange.End);

        if (_lastText.Length <= start || _lastText.Length <= end || start == -1 || end == -1)
            throw new InvalidOperationException("Invalid range.");

        var startIndex = _preprocessedToSource[start];
        var endIndex = _preprocessedToSource[end];

        return new Range(_lastInputText.GetPositionForIndex(startIndex), _lastInputText.GetPositionForIndex(endIndex));
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
