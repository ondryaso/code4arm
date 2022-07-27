// ITokenizer.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;

namespace Code4Arm.LanguageServer.Services.Abstractions;

/// <summary>
/// Used to create semantic tokens based on code analysis. 
/// </summary>
public interface ITokenizer
{
    /// <summary>
    /// Fetches the contents of a given document, finds semantic tokens and inserts them to a given
    /// <see cref="SemanticTokensBuilder"/>.
    /// </summary>
    /// <param name="document">The URI of the document.</param>
    /// <param name="builder">The token builder.</param>
    /// <returns>A Task representing the asynchronous operation.</returns>
    Task Tokenize(DocumentUri document, SemanticTokensBuilder builder);
}
