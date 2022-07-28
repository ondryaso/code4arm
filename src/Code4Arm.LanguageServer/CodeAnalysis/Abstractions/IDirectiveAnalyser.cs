// IDirectiveAnalyser.cs
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

using Code4Arm.LanguageServer.CodeAnalysis.Models;

namespace Code4Arm.LanguageServer.CodeAnalysis.Abstractions;

/// <summary>
/// Represents an analyser for directives.
/// </summary>
public interface IDirectiveAnalyser
{
    /// <summary>
    /// Makes a <see cref="AnalysedDirective"/> for the given source text.
    /// </summary>
    /// <param name="directiveText">The source text with a detected directive.</param>
    /// <param name="directiveStartLinePosition">The line index on which the directive starts.</param>
    /// <param name="sourceAnalyser">The parent source analyser.</param>
    /// <returns>An <see cref="AnalysedDirective"/> object with details of the directive and the analysis result.</returns>
    AnalysedDirective AnalyseDirective(string directiveText, int directiveStartLinePosition,
        ISourceAnalyser sourceAnalyser);
}
