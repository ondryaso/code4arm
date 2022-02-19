// BufferedSource.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Models;

public class BufferedSource : ISource
{
    internal BufferedSource(DocumentUri uri, string text, int? version)
    {
        this.Uri = uri;
        this.Text = text;
        this.Version = version;
        this.IsValidRepresentation = true;
    }

    public bool IsValidRepresentation { get; internal set; }
    public DocumentUri Uri { get; }
    public int? Version { get; internal set; }

    public string Text { get; internal set; }

    public Task<string> GetText()
    {
        return Task.FromResult(this.Text);
    }

    public Task<string> GetText(Range range)
    {
        return Task.FromResult(this[range]);
    }

    // Inspiration for code below (for the time being):
    // https://github.com/gulbanana/thousand/blob/master/Thousand.LSP/BufferService.cs

    // TODO: make a more memory-friendly version that doesn't involve copying strings all the time
    public string this[Range range]
    {
        get
        {
            var start = GetIndexForPosition(this.Text, range.Start);
            var end = GetIndexForPosition(this.Text, range.End);

            return this.Text[start..end];
        }

        internal set
        {
            var start = GetIndexForPosition(this.Text, range.Start);
            var end = GetIndexForPosition(this.Text, range.End);

            this.Text = this.Text[..start] + value + this.Text[end..];
        }
    }

    private static int GetIndexForPosition(string text, Position position)
    {
        var pos = 0;

        for (var i = 0; i < position.Line; i++)
        {
            pos = text.IndexOf('\n', pos) + 1;
        }

        return pos + position.Character;
    }
}
