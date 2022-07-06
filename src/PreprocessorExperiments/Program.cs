using System.IO.Abstractions;
using Code4Arm.LanguageServer.Services;
using Microsoft.Extensions.Logging.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;
using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

var loggerFactory = new NullLoggerFactory();
var store = new FileSourceStore(loggerFactory, new FileSystem());

var testFile = Path.Combine(Environment.CurrentDirectory, "testfile.txt");
var testFileUri = DocumentUri.File(testFile);
var origText = await File.ReadAllTextAsync(testFile);

await store.LoadDocument(new TextDocumentItem() { Uri = testFileUri, Text = origText });

var orig = await store.GetDocument(testFileUri);
var prep = await store.GetPreprocessedDocument(testFileUri);

await File.WriteAllTextAsync("preprocessed.txt", prep.Text);

while (true)
{
    var cmd = Console.ReadLine();
    var parts = cmd.Split(' ');

    if (parts.Length < 3)
        continue;

    try
    {
        if (parts[0] == "o")
        {
            var prepRange = GetRange(parts[1], parts[2]);

            if (prepRange == null) continue;
            var origRange = prep.GetOriginalRange(prepRange);

            Console.WriteLine($"Original range: {origRange}");
            WriteRangedText(orig[origRange], origRange);
        }
        else if (parts[0] == "p")
        {
            var origRange = GetRange(parts[1], parts[2]);

            if (origRange == null) continue;
            var prepRange = prep.GetPreprocessedRange(origRange);

            Console.WriteLine($"Preprocessed range: {prepRange}");
            WriteRangedText(prep[prepRange], prepRange);
        }
        else
        {
            Console.WriteLine("o - get original from preprocessed / p - get preprocessed from original");
        }
    }
    catch (InvalidOperationException)
    {
        Console.WriteLine("Invalid range");
    }
}

void WriteRangedText(string text, Range range)
{
    var min = range.SpansMultipleLines() ? 0 : range.Start.Character;
    var max = range.SpansMultipleLines() ? /*Math.Max(range.Start.Character, range.End.Character)*/0 : range.End.Character;

    if (range.SpansMultipleLines())
    {
        var i = 0;
        var prevI = 0;
        
        while (true)
        {
            var x = i - prevI;
            if (x > max) max = x;

            if (i == text.Length)
                break;
            
            if (i == -1 || i >= text.Length)
            {
                prevI = i;
                i = text.Length;
                continue;
            }
            
            prevI = i;
            i = text.IndexOf('\n', i + 1);
        }

        max++;
    }
    
    Console.Write(min);
    for (var i = (min.ToString()).Length; i < (max - min - 1); i++)
    {
        if ((i + min) % 10 == 0)
        {
            Console.Write(i + min);
            i++;
        }
        else
        {
            Console.Write(' ');
        }
    }

    Console.WriteLine(max - 1);

    for (var i = 0; i < (max - min); i++)
    {
        Console.Write('_');
    }

    Console.WriteLine();
    Console.Write(text.Replace("\n", "\\n\n"));
    Console.WriteLine("|end");
    
    for (var i = 0; i < (max - min); i++)
    {
        Console.Write('_');
    }
    Console.WriteLine();
}

Range? GetRange(string begin, string end)
{
    var bs = begin.IndexOf(':');
    if (bs == -1 || bs == begin.Length - 1)
    {
        Console.WriteLine("Invalid begin position - line:char");

        return null;
    }

    var bl = begin[..bs];
    var bc = begin[(bs + 1)..];

    var es = end.IndexOf(':');
    if (es == -1 || es == (end.Length - 1))
    {
        Console.WriteLine("Invalid ending position - line:char");

        return null;
    }

    var el = end[..es];
    var ec = end[(es + 1)..];

    if (!int.TryParse(bl, out var bli) || !int.TryParse(bc, out var bci) || !int.TryParse(el, out var eli)
        || !int.TryParse(ec, out var eci))
    {
        Console.WriteLine("Invalid number");

        return null;
    }

    return new Range(bli, bci, eli, eci);
}
