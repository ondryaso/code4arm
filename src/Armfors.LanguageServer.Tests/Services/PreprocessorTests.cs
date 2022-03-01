// PreprocessorTests.cs
// Author: Ondřej Ondryáš

using System.Collections.Generic;
using System.IO.Abstractions.TestingHelpers;
using System.Linq;
using System.Threading.Tasks;
using Armfors.LanguageServer.Services;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Tests.Services;

[TestFixture]
public class PreprocessorTests
{
    private static string[] _textNames =
    {
        "BlockCommentOnly", "InverseEmptyLinesMultipleOnly", "InverseEmptyLinesOnly", "InverseOneLineOnly", "Complete"
    };

    private static readonly Dictionary<string, string> SourceTexts = new()
    {
        { "BlockCommentOnly", "This/* a block\ncomment\n\nspanning over multiple\nlines */is a text." },
        { "InverseEmptyLinesMultipleOnly", "Abc\n\ndefg\n\n\nhij\nkl" },
        { "InverseEmptyLinesOnly", "Abc\n\n\ndefg" },
        { "InverseOneLineOnly", "This    is a text.\nThis /* nothing */  is a text." },
        {
            "Complete", @"This is a text.
   

This is // a comment
This /* is a comment */x
This /*
is a
multiline comment */ and text //comment
This is // /* invalid 
*//*  another one */
Mock text line 2

Text     ."
        }
    };

    private static readonly Dictionary<string, string> PreprocessedTexts = new()
    {
        { "BlockCommentOnly", "This is a text." },
        { "InverseEmptyLinesMultipleOnly", "Abc\ndefg\nhij\nkl" },
        { "InverseEmptyLinesOnly", "Abc\ndefg" },
        { "InverseOneLineOnly", "This is a text.\nThis is a text." },
        {
            "Complete",
            @"This is a text.
This is 
This x
This and text 
This is 
*/ 
Mock text line 2
Text ."
        }
    };

    private FileSourceStore _store = null!;

    public static List<(Range Source, Range Preprocessed)> BlockCommentOnlyMatchingRanges = new()
    {
        // First part only - no changes
        (new Range(0, 0, 0, 3), new Range(0, 0, 0, 3)),
        // Second part only - shift
        (new Range(4, 8, 4, 9), new Range(0, 5, 0, 6)),
        // Space between them - expansion
        (new Range(0, 4, 4, 7), new Range(0, 4, 0, 4)),
        // First part and space between them - expansion
        (new Range(0, 0, 4, 7), new Range(0, 0, 0, 4)),
        // Second part and space between them - expansion
        (new Range(0, 4, 4, 9), new Range(0, 4, 0, 6)),
        // Inside
        (new Range(0, 2, 4, 10), new Range(0, 2, 0, 7)),
    };

public static List<(Range Source, Range Preprocessed)> InverseEmptyLinesMultipleOnlyMatchingRanges = new()
    {
        // First line only - no changes
        (new Range(0, 0, 0, 3), new Range(0, 0, 0, 3)),
        // Second line only - line shift
        (new Range(2, 0, 2, 4), new Range(1, 0, 1, 4)),
        // Third line only - line shift
        (new Range(5, 0, 5, 1), new Range(2, 0, 2, 1)),
        // Last line only - line shift
        (new Range(6, 0, 6, 1), new Range(3, 0, 3, 1)),
        // First line and newline - line shift
        (new Range(0, 0, 2, 0), new Range(0, 0, 1, 0)),
        // Only newline from first line to second - line shift
        (new Range(0, 3, 2, 0), new Range(0, 3, 1, 0)),
        // Spanning over multiple replacements
        (new Range(0, 1, 5, 1), new Range(0, 1, 2, 1)),
        // Only one newline
        (new Range(5, 1, 6, 1), new Range(2, 1, 3, 1)),
    };

    public static List<(Range Source, Range Preprocessed)> InverseEmptyLinesOnlyMatchingRanges = new()
    {
        // First line only - no changes
        (new Range(0, 0, 0, 3), new Range(0, 0, 0, 3)),
        // Second line only - line shift
        (new Range(3, 0, 3, 4), new Range(1, 0, 1, 4)),
        // First line and newline - line shift
        (new Range(0, 0, 3, 0), new Range(0, 0, 1, 0)),
        // Only newline from first line to second - line shift
        (new Range(0, 3, 3, 0), new Range(0, 3, 1, 0)),
    };

    public static List<(Range Source, Range Preprocessed)> InverseOneLineOnlyMatchingRanges = new()
    {
        (new Range(0, 0, 0, 4), new Range(0, 0, 0, 4)),
        (new Range(0, 0, 0, 8), new Range(0, 0, 0, 5)),
        (new Range(0, 0, 0, 9), new Range(0, 0, 0, 6)),
        (new Range(0, 4, 0, 4), new Range(0, 4, 0, 4)),
        (new Range(0, 4, 0, 8), new Range(0, 4, 0, 5)),
        (new Range(1, 0, 1, 4), new Range(1, 0, 1, 4)),
        (new Range(1, 0, 1, 20), new Range(1, 0, 1, 5)),
        (new Range(1, 28, 1, 30), new Range(1, 13, 1, 15)),
        (new Range(0, 0, 1, 4), new Range(0, 0, 1, 4)),
        (new Range(0, 8, 1, 4), new Range(0, 5, 1, 4)),
        (new Range(0, 9, 1, 4), new Range(0, 6, 1, 4)),
        (new Range(0, 9, 1, 20), new Range(0, 6, 1, 5)),
    };

    public static List<(Range Source, Range Preprocessed)> CompleteMatchingRanges = new()
    {
        (new Range(0, 0, 0, 4), new Range(0, 0, 0, 4)),
        (new Range(0, 0, 3, 4), new Range(0, 0, 1, 4)),
        (new Range(1, 1, 2, 0), new Range(0, 15, 0, 15)),
        (new Range(3, 0, 3, 13), new Range(1, 0, 1, 7)),
        (new Range(3, 0, 4, 1), new Range(1, 0, 2, 1)),
        (new Range(3, 0, 4, 7), new Range(1, 0, 2, 4)),
        (new Range(4, 9, 4, 13), new Range(2, 4, 2, 4)),
        (new Range(5, 1, 7, 27), new Range(3, 1, 3, 11)),
        (new Range(8, 2, 12, 1), new Range(4, 2, 7, 1)),
        (new Range(8, 9, 9, 0), new Range(4, 7, 5, 0)),
        (new Range(8, 9, 10, 1), new Range(4, 7, 6, 1))
    };

    [SetUp]
    protected void SetUp()
    {
        var logger = new NullLogger<FileSourceStore>();
        var mockFs = new MockFileSystem(_textNames.ToDictionary(n => n, n => new MockFileData(SourceTexts[n])));

        _store = new FileSourceStore(logger, mockFs);
    }

    [TestCaseSource(nameof(_textNames))]
    public async Task TestPreprocessor(string textName)
    {
        var document = this.MakeDocumentItem(textName);
        await _store.LoadDocument(document);
        var preprocessedSource = await _store.GetPreprocessedDocument(document.Uri);

        Assert.That(preprocessedSource.Text, Is.EqualTo(PreprocessedTexts[textName]));
    }

    [TestCaseSource(nameof(CompleteMatchingRanges))]
    public async Task TestGetPreprocessedRange((Range Source, Range Preprocessed) rangePair)
    {
        var document = this.MakeDocumentItem("Complete");
        await _store.LoadDocument(document);
        var preprocessedSource = await _store.GetPreprocessedDocument(document.Uri);

        var (source, prep) = rangePair;
        Assert.That(preprocessedSource.GetPreprocessedRange(source), Is.EqualTo(prep));
    }

    [TestCaseSource(nameof(InverseOneLineOnlyMatchingRanges))]
    public async Task TestGetOriginalRangeOneLineOnly((Range Source, Range Preprocessed) rangePair)
    {
        var document = this.MakeDocumentItem("InverseOneLineOnly");
        await _store.LoadDocument(document);
        var preprocessedSource = await _store.GetPreprocessedDocument(document.Uri);

        var (source, prep) = rangePair;
        Assert.That(preprocessedSource.GetOriginalRange(prep), Is.EqualTo(source));
    }

    [TestCaseSource(nameof(InverseEmptyLinesOnlyMatchingRanges))]
    public async Task TestGetOriginalRangeEmptyLinesOnly((Range Source, Range Preprocessed) rangePair)
    {
        var document = this.MakeDocumentItem("InverseEmptyLinesOnly");
        await _store.LoadDocument(document);
        var preprocessedSource = await _store.GetPreprocessedDocument(document.Uri);

        var (source, prep) = rangePair;
        Assert.That(preprocessedSource.GetOriginalRange(prep), Is.EqualTo(source));
    }

    [TestCaseSource(nameof(InverseEmptyLinesMultipleOnlyMatchingRanges))]
    public async Task TestGetOriginalRangeEmptyLinesMultipleOnly((Range Source, Range Preprocessed) rangePair)
    {
        var document = this.MakeDocumentItem("InverseEmptyLinesMultipleOnly");
        await _store.LoadDocument(document);
        var preprocessedSource = await _store.GetPreprocessedDocument(document.Uri);

        var (source, prep) = rangePair;
        Assert.That(preprocessedSource.GetOriginalRange(prep), Is.EqualTo(source));
    }
    
    [TestCaseSource(nameof(BlockCommentOnlyMatchingRanges))]
    public async Task TestGetOriginalRangeBlockCommentOnly((Range Source, Range Preprocessed) rangePair)
    {
        var document = this.MakeDocumentItem("BlockCommentOnly");
        await _store.LoadDocument(document);
        var preprocessedSource = await _store.GetPreprocessedDocument(document.Uri);

        var (source, prep) = rangePair;
        Assert.That(preprocessedSource.GetOriginalRange(prep), Is.EqualTo(source));
    }

    private TextDocumentItem MakeDocumentItem(string textName)
    {
        return new TextDocumentItem()
        {
            LanguageId = Constants.ArmUalLanguageId,
            Text = SourceTexts[textName],
            Uri = new DocumentUri("file", null, textName, null, null),
            Version = 0
        };
    }
}
