// ILanguageServerConfigurationExtensions.cs
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

using Code4Arm.LanguageServer.Models;
using Microsoft.Extensions.Configuration;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using OmniSharp.Extensions.LanguageServer.Protocol.Server;

namespace Code4Arm.LanguageServer.Extensions;

// ReSharper disable once InconsistentNaming
public static class ILanguageServerConfigurationExtensions
{
    public static Task<EditorOptions> GetServerOptions(
        this ILanguageServerConfiguration configurationContainer, ITextDocumentIdentifierParams document)
    {
        return GetServerOptions(configurationContainer, document.TextDocument.Uri);
    }

    public static async Task<EditorOptions> GetServerOptions(
        this ILanguageServerConfiguration configurationContainer, DocumentUri documentUri)
    {
        var options = new EditorOptions();
        var configuration = await configurationContainer.GetScopedConfiguration(documentUri, CancellationToken.None);

        configuration.GetSection(Constants.ConfigurationSectionRoot).Bind(options);
        configuration.Dispose();

        return options;
    }

    public static async Task<EditorOptions> GetServerOptions(
        this ILanguageServerConfiguration configurationContainer)
    {
        var options = new EditorOptions();
        var configuration = await configurationContainer.GetConfiguration(new ConfigurationItem()
            { Section = Constants.ConfigurationSectionRoot });

        configuration.GetSection(Constants.ConfigurationSectionRoot).Bind(options);

        return options;
    }
}
