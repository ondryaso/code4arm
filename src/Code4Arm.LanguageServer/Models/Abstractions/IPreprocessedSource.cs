// IPreprocessedSource.cs
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
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Code4Arm.LanguageServer.Models.Abstractions;

/// <summary>
/// Represents a preprocessed view of a textual source document.
/// </summary>
public interface IPreprocessedSource : ISource
{
    /// <summary>
    /// The original source that is being preprocessed.  
    /// </summary>
    ISource BaseSource { get; }
    
    /// <summary>
    /// Determines a <see cref="Range"/> in the original source that corresponds to a given <see cref="Range"/>
    /// in its preprocessed version. 
    /// </summary>
    /// <param name="preprocessedRange">The range in the preprocessed document.</param>
    /// <returns>The corresponding range in the original source.</returns>
    Range GetOriginalRange(Range preprocessedRange);
    
    /// <summary>
    /// Determines a <see cref="Range"/> in the preprocessed source that corresponds to a given <see cref="Range"/>
    /// in its original form. 
    /// </summary>
    /// <param name="originalRange">The range in the original document.</param>
    /// <returns>The corresponding range in the preprocessed source.</returns>
    Range GetPreprocessedRange(Range originalRange);
    
    /// <summary>
    /// An enumerable of user-defined folding regions.
    /// </summary>
    /// <remarks>
    /// The user may define custom folding regions using //#region and //#endregion.
    /// </remarks>
    IEnumerable<Range> Regions { get; }
    
    /// <summary>
    /// An enumerable of indices of lines that should be excluded from diagnostics publishing.
    /// </summary>
    /// <remarks>
    /// The user may define suppressed regions using //#suppress and //#endsuppress
    /// or suppress a single line using //!.
    /// </remarks>
    IReadOnlyList<int> SuppressedLines { get; }
    
    /// <summary>
    /// An enumerable of indices of lines that should be excluded from analysis altogether.
    /// </summary>
    /// <remarks>
    /// The user may define ignored regions using //#ignore and //#endignore
    /// or suppress a single line using //!!.
    /// </remarks>
    IReadOnlyList<int> IgnoredLines { get; }

    /// <summary>
    /// Determines a line index in the original source that corresponds to a given line index
    /// in its preprocessed version. 
    /// </summary>
    /// <param name="preprocessedLine">The line index in the preprocessed document.</param>
    /// <returns>The corresponding line index in the original source.</returns>
    int GetOriginalLine(int preprocessedLine)
    {
        return this.GetOriginalRange(new Range(preprocessedLine, 0, preprocessedLine, 0)).Start.Line;
    }

    /// <summary>
    /// Determines a line index in the preprocessed source that corresponds to a given line index
    /// in its original form.
    /// </summary>
    /// <param name="originalLine">The line index in the original document.</param>
    /// <returns>The corresponding line index in the preprocessed source.</returns>
    int GetPreprocessedLine(int originalLine)
    {
        return this.GetPreprocessedRange(new Range(originalLine, 0, originalLine, 0)).Start.Line;
    }

    /// <summary>
    /// Determines a <see cref="Position"/> in the original source that corresponds to a given <see cref="Position"/>
    /// in its preprocessed version. 
    /// </summary>
    /// <param name="preprocessedPosition">The position in the preprocessed document.</param>
    /// <returns>The corresponding position in the original source.</returns>
    Position GetOriginalPosition(Position preprocessedPosition)
    {
        return this.GetOriginalRange(new Range(preprocessedPosition, preprocessedPosition)).End;
    }
    
    /// <summary>
    /// Determines a <see cref="Position"/> in the preprocessed source that corresponds to a given <see cref="Position"/>
    /// in its original form. 
    /// </summary>
    /// <param name="originalPosition">The position in the original document.</param>
    /// <returns>The corresponding position in the preprocessed source.</returns>
    Position GetPreprocessedPosition(Position originalPosition)
    {
        return this.GetPreprocessedRange(new Range(originalPosition, originalPosition)).End;
    }
}
