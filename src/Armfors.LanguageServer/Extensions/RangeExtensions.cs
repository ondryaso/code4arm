// RangeExtensions.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Extensions;

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

public static class RangeExtensions
{
    public static Range Prolong(this Range range, int characters)
    {
        return new Range(new Position(range.Start.Line, range.Start.Character),
            new Position(range.End.Line, range.End.Character + characters));
    }

    public static Range Trail(this Range range, int length)
    {
        return new Range(new Position(range.End.Line, range.End.Character),
            new Position(range.End.Line, range.End.Character + length));
    }
}
