// RangeExtensions.cs
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

using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer.Extensions;

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

public static class RangeExtensions
{
    /// <summary>
    /// Returns a new <see cref="Range"/> with <paramref name="characters"/> added to <see cref="Range.End"/>. 
    /// </summary>
    /// <param name="range">Range [sl, sc, el, ec].</param>
    /// <param name="characters">Number of characters to add.</param>
    /// <returns>Range [sl, sc, el, ec + <paramref name="characters"/>].</returns>
    public static Range Prolong(this Range range, int characters)
    {
        return new Range(range.Start.Line, range.Start.Character,
            range.End.Line, range.End.Character + characters);
    }

    /// <summary>
    /// Returns a new <see cref="Range"/> adjusted to the first '<paramref name="characters"/>' characters of the first line. 
    /// </summary>
    /// <param name="range">Range [sl, sc, el, ec].</param>
    /// <param name="characters">Number of characters.</param>
    /// <returns>Range [sl, sc, sl, sc + <paramref name="characters"/>].</returns>
    public static Range Take(this Range range, int characters)
    {
        return new Range(range.Start.Line, range.Start.Character,
            range.Start.Line, range.Start.Character + characters);
    }

    /// <summary>
    /// Returns a new <see cref="Range"/> of a given <paramref name="length"/> that follows the given range.
    /// </summary>
    /// <param name="range">Range [sl, sc, el, ec].</param>
    /// <param name="length">The length.</param>
    /// <param name="offset">An offset.</param>
    /// <returns>Range [el, ec + offset, el, ec + offset + length</returns>
    public static Range Trail(this Range range, int length, int offset = 0)
    {
        return new Range(range.End.Line, range.End.Character + offset, 
            range.End.Line, range.End.Character + offset + length);
    }
}
