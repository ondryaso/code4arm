// PreprocessorTests.cs
// Author: Ondřej Ondryáš

using System.Collections.Generic;
using System.IO.Abstractions.TestingHelpers;
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
    private const string MockFileName = "file";

    private const string MockFileText = @"This is a text.


This is // a comment
This /* is a comment */
This /*
is a
multiline comment */ and text
This is // /* invalid 
*//*  another one */
Mock text line 2

Text.";

    private const string MockFilePreprocessedText = @"This is a text.
This is 
This 
This and text
This is 
*/ 
Mock text line 2
Text.";

    private FileSourceStore _store = null!;
    private DocumentUri _mockFileUri = null!;

    [SetUp]
    protected void SetUp()
    {
        var logger = new NullLogger<FileSourceStore>();
        var mockFs = new MockFileSystem(new Dictionary<string, MockFileData>()
        {
            { MockFileName, new MockFileData(MockFileText) }
        });

        _store = new FileSourceStore(logger, mockFs);
        _mockFileUri = new DocumentUri("file", null, MockFileName, null, null);
    }

    [Test]
    public async Task TestPreprocessor()
    {
        await _store.LoadDocument(this.MakeDocumentItem());
        var preprocessedSource = await _store.GetPreprocessedDocument(_mockFileUri);
        Assert.That(preprocessedSource.Text, Is.EqualTo(MockFilePreprocessedText));
    }

    private TextDocumentItem MakeDocumentItem()
    {
        return new TextDocumentItem()
        {
            LanguageId = Constants.ArmUalLanguageId,
            Text = MockFileText,
            Uri = _mockFileUri,
            Version = 0
        };
    }
}
