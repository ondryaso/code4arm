// Constants.cs
// Author: Ondřej Ondryáš

using System.Collections.Immutable;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer;

public static class Constants
{
    /// Language ID for the Arm assembly language as defined in the client extension.
    public const string ArmUalLanguageId = "arm-ual";
    
    /// <summary>
    /// A document selector for our language ID.
    /// Using this lets the client extension control what files are considered Arm source files.
    /// </summary>
    public static readonly DocumentSelector ArmUalDocumentSelector = DocumentSelector.ForLanguage(ArmUalLanguageId);

    public const string ServiceSource = "code4arm";

    public const string ArmUalLanguageName = "Arm UAL";

    public const string ConfigurationSectionRoot = "code4arm.editor";

    public static readonly ImmutableList<string> SimulatedFunctions = ImmutableList<string>.Empty.AddRange(new []
    {
        "calloc", "malloc", "free", "realloc",
        "getchar", "putchar", "printf", "puts", "ungetc",
        "ReadInt32", "ReadUInt32", "ReadInt64", "ReadUInt64", "ReadFloat32", "ReadFloat64"
    });
}
