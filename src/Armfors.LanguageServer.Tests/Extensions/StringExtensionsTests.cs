// StringExtensionsTests.cs
// Author: Ondřej Ondryáš

using System.Collections.Generic;
using System.Linq;
using Armfors.LanguageServer.Extensions;
using NUnit.Framework;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.Tests.Extensions;

[TestFixture]
public class StringExtensionsTests
{
    public const string InputText = "0123\n567\n9\n\nX";

    public static readonly Position[] Positions =
    {
        new(0, 0),
        new(0, 1),
        new(0, 2),
        new(0, 3),
        new(0, 4),
        new(1, 0),
        new(1, 1),
        new(1, 2),
        new(1, 3),
        new(2, 0),
        new(2, 1),
        new(3, 0),
        new(4, 0)
    };

    public static IEnumerable<int> PossibleIndices => Enumerable.Range(0, InputText.Length);

    [TestCaseSource(nameof(PossibleIndices))]
    public void TestGetPositionForIndex(int index)
    {
        Assert.That(InputText.GetPositionForIndex(index), Is.EqualTo(Positions[index]));
    }

    [Test]
    public void TestGetPositionForIndexInvalidValues()
    {
        var invalidPos = new Position(-1, -1);
        Assert.That(InputText.GetPositionForIndex(-1), Is.EqualTo(invalidPos));
        Assert.That(InputText.GetPositionForIndex(InputText.Length), Is.EqualTo(invalidPos));
    }

    [TestCaseSource(nameof(PossibleIndices))]
    public void TextGetIndexForPosition(int index)
    {
        Assert.That(InputText.GetIndexForPosition(Positions[index]), Is.EqualTo(index));
    }

    [TestCase(-1, -1)]
    [TestCase(0, 5)]
    [TestCase(0, 6)]
    [TestCase(4, 2)]
    [TestCase(6, 0)]
    [TestCase(6, 1)]
    [TestCase(7, 0)]
    public void TestGetIndexForPositionInvalidValues(int line, int character)
    {
        Assert.That(InputText.GetIndexForPosition(line, character), Is.EqualTo(-1));
    }
}
