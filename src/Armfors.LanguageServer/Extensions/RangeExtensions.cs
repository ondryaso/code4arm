// RangeExtensions.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Extensions;

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

public static class RangeExtensions
{
    public static Range Prolong(this Range range, int characters)
    {
        return new Range(range.Start.Line, range.Start.Character,
            range.End.Line, range.End.Character + characters);
    }

    public static Range Take(this Range range, int characters)
    {
        return new Range(range.Start.Line, range.Start.Character,
            range.End.Line, range.Start.Character + characters);
    }

    public static Range Trail(this Range range, int length, int offset = 0)
    {
        return new Range(range.End.Line, range.End.Character + offset, 
            range.End.Line, range.End.Character + length);
    }
}
