// ISymbolDocumentationProvider.cs
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

namespace Code4Arm.LanguageServer.Services.Abstractions;

/// <summary>
/// Provides documentation for language symbols (like register names or condition codes).  
/// </summary>
public interface ISymbolDocumentationProvider
{
    /// <summary>
    /// Returns documentation for a given key.
    /// </summary>
    /// <param name="key">The documentation key.</param>
    MarkupContent? this[string key] { get; }

    /// <summary>
    /// Returns documentation for a given enum value.
    /// </summary>
    /// <param name="enumValue">The enum value.</param>
    /// <param name="tag">An optional tag determining the context of the enum's usage.
    /// If null, <see cref="ILocalizationService.CompletionDocumentationTag"/> is used.</param>
    /// <typeparam name="T">The enum type.</typeparam>
    MarkupContent? EnumEntry<T>(T enumValue, string? tag = null) where T : struct, Enum
    {
        return this[
            ILocalizationService.GetEnumEntryIdentifier(enumValue,
                tag ?? ILocalizationService.CompletionDocumentationTag)];
    }
}
