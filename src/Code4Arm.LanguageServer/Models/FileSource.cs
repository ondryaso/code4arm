// FileSource.cs
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

using System.IO.Abstractions;
using System.Text;
using Code4Arm.LanguageServer.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.Models;

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

    public string this[Range range] => throw new NotImplementedException();

    public string this[int line] => throw new NotImplementedException();

    public IEnumerable<string> GetLines()
    {
        using var reader = _fileInfo.OpenText();
        while (!reader.EndOfStream)
        {
            var read = reader.ReadLine();
            if (read == null) yield break;
            yield return read;
        }
    }

    public async Task<string> GetTextAsync()
    {
        // TODO: optimise this to use pre-allocated memory
        // or at least check modification times and use cached results

        using var reader = _fileInfo.OpenText();
        return await reader.ReadToEndAsync();
    }

    public async Task<string> GetTextAsync(Range range)
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

        if (startLine > line || endLine > line || range.Start.Character > firstLineLength ||
            range.End.Character > lastLineLength)
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

    public async Task<string> GetTextAsync(int line)
    {
        using var reader = _fileInfo.OpenText();
        var currentLine = 0;
        while (!reader.EndOfStream)
        {
            var read = await reader.ReadLineAsync();
            if (currentLine++ != line) continue;
            return read ?? throw new ArgumentException("Invalid line.", nameof(line));
        }

        throw new ArgumentException("Invalid line.", nameof(line));
    }

    public async IAsyncEnumerable<string> GetLinesAsyncEnumerable()
    {
        using var reader = _fileInfo.OpenText();
        while (!reader.EndOfStream)
        {
            var read = await reader.ReadLineAsync();
            if (read == null) yield break;
            yield return read;
        }
    }

    public bool SupportsSyncOperations => false;
    public bool SupportsAsyncOperations => true;
    public bool SupportsSyncLineIterator => true;
    public bool SupportsAsyncLineIterator => true;
}
