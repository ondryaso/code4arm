// PreprocessedSource.cs
// Author: Ondřej Ondryáš

using System.Text.RegularExpressions;
using Armfors.LanguageServer.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Models;

public class PreprocessedSource : BufferedSourceBase, IPreprocessedSource
{
    internal PreprocessedSource(ISource baseSource)
    {
        this.BaseSource = baseSource;
        _text = string.Empty;
    }

    private readonly Regex _singleLineCommentsRegex =
        new(@"(?:(?!\*)\/\/(?!\*)|@).*$", RegexOptions.Compiled | RegexOptions.Multiline);

    private readonly Regex _multiLineCommentsRegex = new(@"\/\*(?:.|\s)*?\*\/", RegexOptions.Compiled);
    private readonly Regex _multipleSpacesRegex = new(@"[ \t]{2,}", RegexOptions.Compiled);
    private readonly Regex _emptyLinesRegex = new(@"\n(?:\s*\n)+", RegexOptions.Compiled);

    internal Task Preprocess(Range? modifiedRange)
    {
        // TODO: Use ranges

        // The order here is important
        _text = this.BaseSource.Text;
        // Replace single-line comments with a single space
        _text = _singleLineCommentsRegex.Replace(_text, " ");
        // Replace multi-line comments with a single space, take note of lines that have been shifted as a result
        _text = _multiLineCommentsRegex.Replace(_text, match => match.Result(" "));
        // Replace multiple consecutive whitespaces with a single space
        _text = _multipleSpacesRegex.Replace(_text, " ");
        // Get rid of all empty lines, take note of lines that have been shifted as a result
        _text = _emptyLinesRegex.Replace(_text, match => match.Result("\n"));
        
        return Task.CompletedTask;
    }

    public override bool IsValidRepresentation => this.BaseSource.IsValidRepresentation;

    public override DocumentUri Uri => this.BaseSource.Uri;

    public override int? Version => this.BaseSource.Version;

    private string _text;

    public override string Text
    {
        get => _text;
        internal set =>
            throw new InvalidOperationException("Text must be set on the base source and preprocessed after.");
    }

    public ISource BaseSource { get; }

    public Range GetOriginalRange(Range preprocessedRange)
    {
        throw new NotImplementedException();
    }

    public Range GetPreprocessedRange(Range originalRange)
    {
        
        throw new NotImplementedException();
    }
}
