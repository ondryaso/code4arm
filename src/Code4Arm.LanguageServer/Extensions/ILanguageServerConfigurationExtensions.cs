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
