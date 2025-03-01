// StringExtensions.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer.Extensions;

public static class StringExtensions
{
    /// <summary>
    /// Returns an index in a text corresponding to a given position in this text.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <param name="line">Index of the line to get text index in.</param>
    /// <param name="character">Index of the character relative to the given line.</param>
    /// <returns>The index in <paramref name="text"/> or -1 if <paramref name="character"/> is higher
    /// than the length of the corresponding line in the text.</returns>
    public static int GetIndexForPosition(this string text, int line, int character)
    {
        var pos = 0;
        for (var i = 0; i < line; i++)
        {
            if (pos > text.Length)
            {
                return -1;
            }

            pos = text.IndexOf('\n', pos) + 1;

            if (pos == 0)
            {
                // End of file with no terminating \n reached
                return -1;
            }
        }

        var nextLineEndPosition = text.IndexOf('\n', pos);
        if (nextLineEndPosition == -1)
        {
            // No \n at the end of the last line
            nextLineEndPosition = text.Length;
        }

        if (pos + character > nextLineEndPosition)
        {
            return -1;
        }

        return pos + character;
    }

    /// <summary>
    /// Returns an index in a text corresponding to a given <see cref="Position"/> in this text.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <param name="position">The position to get text index for.</param>
    /// <returns>The index in <paramref name="text"/> or -1 if the position's <see cref="Position.Character"/> is higher
    /// than the length of the corresponding line in the text.</returns>
    public static int GetIndexForPosition(this string text, Position position)
        => GetIndexForPosition(text, position.Line, position.Character);

    /// <summary>
    /// Returns a <see cref="Position"/> corresponding to a given character index in a text. 
    /// </summary>
    /// <param name="text">The text.</param>
    /// <param name="index">The index in the text.</param>
    /// <returns>A <see cref="Position"/>. If the index is outside the text, an invalid <see cref="Position"/> set to
    /// (-1, -1) is returned.</returns>
    public static Position GetPositionForIndex(this string text, int index)
    {
        if (index < 0 || index >= text.Length)
        {
            return new Position(-1, -1); // Invalid position!
        }

        var pos = 0;
        var line = 0;
        var lastLineStartIndex = 0;

        while (pos <= index)
        {
            lastLineStartIndex = pos;
            pos = text.IndexOf('\n', pos) + 1;
            line++;

            if (pos < lastLineStartIndex)
            {
                // Handles last lines with no \n at the end
                break;
            }
        }

        return new Position(line - 1, index - lastLineStartIndex);
    }
}
