// ITokenizer.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;

namespace Armfors.LanguageServer.Services.Abstractions;

public interface ITokenizer
{
    void Tokenize(DocumentUri document, SemanticTokensBuilder builder);
}
