// ISource.cs
// Author: Ondřej Ondryáš

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Models.Abstractions;

public interface ISource
{
    public string Text { get; }
    public string this[Range range] { get; }
}
