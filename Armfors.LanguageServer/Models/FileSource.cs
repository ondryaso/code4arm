// FileSource.cs
// Author: Ondřej Ondryáš

using System.IO.Abstractions;
using System.Text;
using Armfors.LanguageServer.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Models;

public class FileSource : ISource
{
    private readonly IFileInfo _fileInfo;

    public FileSource(DocumentUri uri, IFileSystem fileSystem)
    {
        this.Uri = uri;

        if (!uri.Scheme?.Equals("file", StringComparison.InvariantCultureIgnoreCase) ?? false)
        {
            throw new ArgumentException(
                $"The scheme of the provided URI must be 'file' (actual value: '{uri.Scheme}').", nameof(uri));
        }

        // TODO: the implementation of this seems fishy regarding Unicode characters in paths; test thoroughly!
        var fsPath = uri.GetFileSystemPath();
        _fileInfo = fileSystem.FileInfo.FromFileName(fsPath);

        if (!_fileInfo.Exists)
        {
            throw new FileNotFoundException("The file specified by the provided URI does not exist.", fsPath);
        }

        this.IsValidRepresentation = true;
    }

    public bool IsValidRepresentation { get; internal set; }
    public DocumentUri Uri { get; }
    public int? Version => null;

    public string Text
    {
        get
        {
            using var sr = _fileInfo.OpenText();
            return sr.ReadToEnd();
        }
    }

    public string this[Range range]
    {
        get { throw new NotImplementedException(); }
    }

    public async Task<string> GetText()
    {
        // TODO: optimise this to use pre-allocated memory
        // or at least check modification times and use cached results

        using var reader = _fileInfo.OpenText();
        return await reader.ReadToEndAsync();
    }

    public async Task<string> GetText(Range range)
    {
        // TODO: optimise
        if (range.Start == range.End)
        {
            return string.Empty;
        }
        
        using var reader = _fileInfo.OpenText();
        var sb = new StringBuilder();

        var startLine = range.Start.Line;
        var endLine = range.End.Line;

        if (startLine > endLine || startLine < 0 || endLine < 0 || range.Start.Character < 0 || range.End.Character < 0)
        {
            throw new ArgumentException("Invalid range.", nameof(range));
        }

        var line = -1;
        var firstLineLength = 0;
        var lastLineLength = 0;

        while (!reader.EndOfStream)
        {
            var lineText = await reader.ReadLineAsync();

            if (lineText is null)
            {
                break;
            }

            lastLineLength = lineText.Length;
            line++;

            if (line < startLine)
            {
                continue;
            }

            if (line == startLine)
            {
                firstLineLength = lineText.Length;
            }
            
            if (line == endLine)
            {
                // Append without newline at the end
                sb.Append(lineText);
                break;
            }
            
            sb.AppendLine(lineText);
        }

        if (startLine > line || endLine > line || range.Start.Character > firstLineLength || range.End.Character > lastLineLength)
        {
            throw new ArgumentException("Invalid range.", nameof(range));
        }

        if (range.Start.Character > 0)
        {
            sb.Remove(0, range.Start.Character);
        }

        if (range.End.Character < lastLineLength)
        {
            sb.Remove(sb.Length - lastLineLength + range.End.Character, lastLineLength - range.End.Character);
        }
        
        return sb.ToString();
    }
}
