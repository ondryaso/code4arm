// IDiagnosticsPublisher.cs
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

using Code4Arm.LanguageServer.CodeAnalysis.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;

namespace Code4Arm.LanguageServer.Services.Abstractions;

/// <summary>
/// Used to determine and push diagnostics (errors, warnings etc.) after finishing code analysis. 
/// </summary>
public interface IDiagnosticsPublisher
{
    /// <summary>
    /// Determines the diagnostics based on the state of a given <see cref="ISourceAnalyser"/> and sends them to the client.
    /// </summary>
    Task PublishAnalysisResult(ISourceAnalyser analyser, DocumentUri documentUri, int? documentVersion);

    /// <summary>
    /// Clears the shown diagnostics for a given file.
    /// </summary>
    Task ClearDiagnostics(DocumentUri documentUri, int? documentVersion);
}
