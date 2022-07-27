// BufferedSource.cs
// Author: Ondřej Ondryáš

using Code4Arm.LanguageServer.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;

namespace Code4Arm.LanguageServer.Models;

public class BufferedSource : BufferedSourceBase
{
    internal BufferedSource(DocumentUri uri, int? version, Func<BufferedSource, IPreprocessorSource> makePreprocessor)
    {
        this.Uri = uri;
        VersionInternal = version;
        IsValidRepresentationInternal = true;
        this.PreprocessedSource = makePreprocessor(this);
    }

    internal IPreprocessorSource PreprocessedSource { get; }

    internal bool IsValidRepresentationInternal;
    public override bool IsValidRepresentation => IsValidRepresentationInternal;

    internal int? VersionInternal;
    public override int? Version => VersionInternal;

    public override DocumentUri Uri { get; }

    private string _text = null!;

    public override string Text
    {
        get => _text;
        internal set => _text = value.Replace("\r\n", "\n").Replace('\r', '\n') + '\n';
    }
}
