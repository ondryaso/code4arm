// BufferedSourceBase.cs
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

using Code4Arm.LanguageServer.Extensions;
using Code4Arm.LanguageServer.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.Models;

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
            var start = this.Text.GetIndexForPosition(range.Start);
            var end = this.Text.GetIndexForPosition(range.End);

            if (start == -1 || end == -1) throw new ArgumentException("Invalid range.", nameof(range));

            return this.Text[start..end];
        }

        internal set
        {
            var start = this.Text.GetIndexForPosition(range.Start);
            var end = this.Text.GetIndexForPosition(range.End);

            if (start == -1 || end == -1) throw new ArgumentException("Invalid range.", nameof(range));

            this.Text = this.Text[..start] + value + this.Text[end..];
        }
    }

    public string this[int line]
    {
        get
        {
            var start = this.Text.GetIndexForPosition(line, 0);
            var end = this.Text.GetIndexForPosition(line + 1, 0);

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
}
