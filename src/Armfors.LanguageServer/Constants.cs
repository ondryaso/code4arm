// Constants.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer;

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

    public const string ConfigurationSectionRoot = "code4arm";
}
