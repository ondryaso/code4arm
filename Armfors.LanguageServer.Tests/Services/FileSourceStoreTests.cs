// FileSourceStoreTests.cs
// Author: Ondřej Ondryáš

using System;
using System.Collections.Generic;
using System.IO.Abstractions.TestingHelpers;
using System.Text;
using System.Threading.Tasks;
using Armfors.LanguageServer.Models;
using Armfors.LanguageServer.Services;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

namespace Armfors.LanguageServer.Tests.Services;

[TestFixture]
public class FileSourceStoreTests
{
    private FileSourceStore _store = null!;
    private DocumentUri _mockFileUri = null!;

    private const string MockFileName = "file";
    private const string MockFileText = "Mock text\nMock text line 2";

    private static Range[] _testRanges =
    {
        new(0, 0, 1, 16),
        new(0, 0, 0, 9),
        new(0, 0, 0, 10),
        new(0, 0, 1, 0),
        new(1, 0, 1, 16),
        new(1, 0, 1, 17),
        new(0, 9, 1, 0),
        new(0, 2, 0, 2),
        new(0, 2, 0, 4)
    };

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
    public void DocumentLifecycle()
    {
        var documentItem = this.MakeDocumentItem();
        
        Assert.That(async () => await _store.IsOpen(documentItem.Uri), Is.False);
        Assert.That(async () => await _store.LoadDocument(documentItem), Throws.Nothing);
        Assert.That(async () => await _store.IsOpen(documentItem.Uri), Is.True);
        Assert.That(async () => await _store.CloseDocument(documentItem.Uri), Throws.Nothing);
        Assert.That(async () => await _store.IsOpen(documentItem.Uri), Is.False);
    }

    [Test]
    public async Task DocumentOwnershipSwitching()
    {
        var documentItem = new TextDocumentItem()
        {
            LanguageId = Constants.ArmUalLanguageId,
            Text = MockFileText,
            Uri = _mockFileUri,
            Version = 0
        };

        var fileSource = await _store.GetDocument(documentItem.Uri);
        Assert.That(fileSource is FileSource);
        Assert.That(fileSource.IsValidRepresentation);
        Assert.That(async () => await _store.ApplyFullChange(fileSource.Uri, "Test", 1), Throws.Exception);

        await _store.LoadDocument(documentItem);
        var bufferedSource = await _store.GetDocument(documentItem.Uri);
        Assert.That(bufferedSource is BufferedSource);
        Assert.That(bufferedSource.IsValidRepresentation);
        Assert.That(fileSource.IsValidRepresentation, Is.False);
        Assert.That(async () => await _store.ApplyFullChange(fileSource.Uri, "Test", 1), Throws.Nothing);

        await _store.CloseDocument(documentItem.Uri);
        Assert.That(bufferedSource.IsValidRepresentation, Is.False);
        Assert.That(fileSource.IsValidRepresentation, Is.True);
    }

    [Test]
    public async Task FileSourceWholeTextAsync()
    {
        var fileSource = await _store.GetDocument(_mockFileUri);
        Assert.That(async () => await fileSource.GetText(), Is.EqualTo(MockFileText));
    }

    [Test]
    public async Task FileSourceWholeTextSync()
    {
        var fileSource = await _store.GetDocument(_mockFileUri);
        Assert.That(() => fileSource.Text, Is.EqualTo(MockFileText));
    }

    [Test]
    [TestCaseSource(nameof(_testRanges))]
    public async Task FileSourceRangeAsync(Range range)
    {
        var fileSource = await _store.GetDocument(_mockFileUri);
        var expectedOutput = Splice(MockFileText, range);

        if (expectedOutput is null)
        {
            Assert.That(async () => await fileSource.GetText(range), Throws.ArgumentException);
        }
        else
        {
            Assert.That(async () => await fileSource.GetText(range), Is.EqualTo(expectedOutput));
        }
    }
    
    [Test]
    public async Task BufferedSourceWholeTextAsync()
    {
        var documentItem = this.MakeDocumentItem();
        await _store.LoadDocument(documentItem);
        var bufferedSource = await _store.GetDocument(_mockFileUri);
        
        Assert.That(async () => await bufferedSource.GetText(), Is.EqualTo(MockFileText));
    }

    [Test]
    public async Task BufferedSourceWholeTextSync()
    {
        var documentItem = this.MakeDocumentItem();
        await _store.LoadDocument(documentItem);
        var bufferedSource = await _store.GetDocument(_mockFileUri);
        
        Assert.That(() => bufferedSource.Text, Is.EqualTo(MockFileText));
    }

    [Test]
    [TestCaseSource(nameof(_testRanges))]
    public async Task BufferedSourceRangeAsync(Range range)
    {
        var documentItem = this.MakeDocumentItem();
        await _store.LoadDocument(documentItem);
        var bufferedSource = await _store.GetDocument(_mockFileUri);
        
        var expectedOutput = Splice(MockFileText, range);

        if (expectedOutput is null)
        {
            Assert.That(async () => await bufferedSource.GetText(range), Throws.ArgumentException);
        }
        else
        {
            Assert.That(async () => await bufferedSource.GetText(range), Is.EqualTo(expectedOutput));
        }
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

    private static string? Splice(string text, Range range)
    {
        // This method is rather awful but it is intentionally implemented in a different way to the one
        // in BufferedSource
        var lines = text.ReplaceLineEndings("\n").Split('\n');
        var sb = new StringBuilder();

        if (range.Start.Character < 0 || range.End.Character < 0 || range.Start.Line < 0 || range.End.Line < 0
            || range.Start.Line > range.End.Line || range.Start.Line >= lines.Length || range.End.Line >= lines.Length)
        {
            return null;
        }

        for (var i = range.Start.Line; i <= range.End.Line; i++)
        {
            if (i == range.Start.Line)
            {
                if (range.Start.Character > lines[i].Length)
                {
                    return null;
                }

                if (range.Start.Line == range.End.Line)
                {
                    if (range.End.Character > lines[i].Length)
                    {
                        return null;
                    }

                    sb.Append(lines[i][range.Start.Character..range.End.Character]);
                }
                else
                {
                    sb.AppendLine(lines[i][range.Start.Character..]);
                }
            }
            else if (i == range.End.Line)
            {
                if (range.End.Character > lines[i].Length)
                {
                    return null;
                }

                if (range.End.Character != 0)
                {
                    sb.Append(lines[i][..Math.Min(range.End.Character, lines[i].Length)]);
                }
            }
            else
            {
                sb.AppendLine(lines[i]);
            }
        }

        return sb.ToString();
    }
}
