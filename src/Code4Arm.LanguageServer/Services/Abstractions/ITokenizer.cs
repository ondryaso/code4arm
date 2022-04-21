// ITokenizer.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Document;

namespace Code4Arm.LanguageServer.Services.Abstractions;

public interface ITokenizer
{
    Task Tokenize(DocumentUri document, SemanticTokensBuilder builder);
}
