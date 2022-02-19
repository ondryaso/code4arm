// BufferedSource.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.Models.Abstractions;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Models;

public class BufferedSource : ISource
{
    public string Text { get; }

    public string this[Range range] => throw new NotImplementedException();
}
