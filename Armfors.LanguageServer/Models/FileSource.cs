// FileSource.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.Models.Abstractions;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Models;

public class FileSource : ISource
{
    public string Text { get; }

    public string this[Range range] => throw new NotImplementedException();
}
