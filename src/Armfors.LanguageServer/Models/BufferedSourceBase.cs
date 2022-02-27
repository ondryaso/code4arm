// BufferedSourceBase.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Models;

public abstract class BufferedSourceBase : ISource
{
    public abstract bool IsValidRepresentation { get; }
    public abstract DocumentUri Uri { get; }
    public abstract int? Version { get; }
    public virtual string Text { get; internal set; } = string.Empty;

    // Inspiration for code below (for the time being):
    // https://github.com/gulbanana/thousand/blob/master/Thousand.LSP/BufferService.cs

    // TODO: make a more memory-friendly version that doesn't involve copying strings all the time
    public string this[Range range]
    {
        get
        {
            var start = GetIndexForPosition(this.Text, range.Start);
            var end = GetIndexForPosition(this.Text, range.End);

            if (start == -1 || end == -1) throw new ArgumentException("Invalid range.", nameof(range));

            return this.Text[start..end];
        }

        internal set
        {
            var start = GetIndexForPosition(this.Text, range.Start);
            var end = GetIndexForPosition(this.Text, range.End);

            if (start == -1 || end == -1) throw new ArgumentException("Invalid range.", nameof(range));

            this.Text = this.Text[..start] + value + this.Text[end..];
        }
    }

    public string this[int line]
    {
        get
        {
            var start = GetIndexForPosition(this.Text, line, 0);
            var end = GetIndexForPosition(this.Text, line + 1, 0);

            if (start == -1 || end == -1) throw new ArgumentException("Invalid line.", nameof(line));

            return this.Text[start..end];
        }
    }

    public Task<string> GetTextAsync()
    {
        return Task.FromResult(this.Text);
    }

    public Task<string> GetTextAsync(Range range)
    {
        return Task.FromResult(this[range]);
    }

    public Task<string> GetTextAsync(int line)
    {
        return Task.FromResult(this[line]);
    }

    public IEnumerable<string> GetLines()
    {
        var replaced = this.Text.ReplaceLineEndings("\n");
        // TODO: fix for strings with no newline character at the end
        var pos = 0;
        while (true)
        {
            var newPos = replaced.IndexOf('\n', pos) + 1;
            if (newPos == 0)
            {
                yield return this.Text[pos..];
                break;
            }

            yield return this.Text[pos..newPos];
            pos = newPos;
        }
    }

#pragma warning disable CS1998
    public async IAsyncEnumerable<string> GetLinesAsyncEnumerable()
    {
        foreach (var line in this.GetLines())
        {
            yield return line;
        }
    }
#pragma warning restore CS1998

    public bool SupportsSyncOperations => true;
    public bool SupportsAsyncOperations => true;
    public bool SupportsSyncLineIterator => true;
    public bool SupportsAsyncLineIterator => true;

    /// <summary>
    /// Returns an index in a text corresponding to a given position in this text.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <param name="line">Index of the line to get text index in.</param>
    /// <param name="character">Index of the character relative to the given line.</param>
    /// <returns>The index in <paramref name="text"/> or -1 if <paramref name="character"/> is higher
    /// than the length of the corresponding line in the text.</returns>
    protected static int GetIndexForPosition(string text, int line, int character)
    {
        var pos = 0;
        for (var i = 0; i < line; i++)
        {
            if (pos > text.Length)
            {
                return -1;
            }

            pos = text.IndexOf('\n', pos) + 1;

            if (pos == 0)
            {
                // End of file with no terminating \n reached
                return character == 0 ? text.Length : -1;
            }
        }

        var nextLineEndPosition = text.IndexOf('\n', pos);
        if (nextLineEndPosition == -1)
        {
            // No \n at the end of the last line
            nextLineEndPosition = text.Length;
        }

        if (pos + character > nextLineEndPosition)
        {
            return -1;
        }

        return pos + character;
    }

    /// <summary>
    /// Returns an index in a text corresponding to a given <see cref="Position"/> in this text.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <param name="position">The position to get text index for.</param>
    /// <returns>The index in <paramref name="text"/> or -1 if the position's <see cref="Position.Character"/> is higher
    /// than the length of the corresponding line in the text.</returns>
    protected static int GetIndexForPosition(string text, Position position)
        => GetIndexForPosition(text, position.Line, position.Character);
}
