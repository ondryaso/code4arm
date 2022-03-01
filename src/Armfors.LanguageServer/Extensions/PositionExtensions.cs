// PositionExtensions.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Extensions;

public static class PositionExtensions
{
    /// <summary>
    /// Copies position data from one <see cref="Position"/> object to another.
    /// </summary>
    /// <param name="position">The object to put data into.</param>
    /// <param name="other">The object to take data from.</param>
    public static void CopyFrom(this Position position, Position other)
    {
        position.Character = other.Character;
        position.Line = other.Line;
    }
}
