// InlineLocalizationService.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Services.Abstractions;
using L = Armfors.LanguageServer.Services.Abstractions.ILocalizationService;

namespace Armfors.LanguageServer.Services;

public class InlineLocalizationService : ILocalizationService
{
    private const string CompLabel = L.CompletionLabelTag;
    private const string CompLabelSimd = L.CompletionLabelSimdTag;
    private const string CompDescription = L.CompletionDescriptionTag;
    private const string CompDescriptionSimd = L.CompletionDescriptionSimdTag;
    private const string CompDocumentation = L.CompletionDocumentationTag;
    private const string CompDocumentationSimd = L.CompletionDocumentationSimdTag;

    private readonly Dictionary<string, string> _values = new()
    {
        { L.GetEnumEntryIdentifier(ConditionCode.AL, CompLabel), "-AL (Always)" },
        { L.GetEnumEntryIdentifier(ConditionCode.CC, CompLabel), "-CC (Carry clear)" },
        { L.GetEnumEntryIdentifier(ConditionCode.CS, CompLabel), "-CS (Carry set)" },
        { L.GetEnumEntryIdentifier(ConditionCode.EQ, CompLabel), "-EQ (Equal)" },
        { L.GetEnumEntryIdentifier(ConditionCode.GE, CompLabel), "-GE (Signed >=)" },
        { L.GetEnumEntryIdentifier(ConditionCode.GT, CompLabel), "-GT (Signed >)" },
        { L.GetEnumEntryIdentifier(ConditionCode.HI, CompLabel), "-HI (Unsigned >)" },
        { L.GetEnumEntryIdentifier(ConditionCode.HS, CompLabel), "-HS (Unsigned >=)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LE, CompLabel), "-LE (Signed <=)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LO, CompLabel), "-LO (Unsigned <)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LS, CompLabel), "-LS (Unsigned <=)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LT, CompLabel), "-LT (Signed <)" },
        { L.GetEnumEntryIdentifier(ConditionCode.MI, CompLabel), "-MI (Negative)" },
        { L.GetEnumEntryIdentifier(ConditionCode.NE, CompLabel), "-NE (Not equal)" },
        { L.GetEnumEntryIdentifier(ConditionCode.PL, CompLabel), "-PL (Positive/zero)" },
        { L.GetEnumEntryIdentifier(ConditionCode.VC, CompLabel), "-VC (Overflow clear)" },
        { L.GetEnumEntryIdentifier(ConditionCode.VS, CompLabel), "-VS (Overflow set)" },

        { L.GetEnumEntryIdentifier(ConditionCode.AL, CompDescription), "Always" },
        { L.GetEnumEntryIdentifier(ConditionCode.CC, CompDescription), "Carry clear / Unsigned < (C == 0)" },
        { L.GetEnumEntryIdentifier(ConditionCode.CS, CompDescription), "Carry set / Unsigned >= (C == 1)" },
        { L.GetEnumEntryIdentifier(ConditionCode.EQ, CompDescription), "Equal (Z == 1)" },
        { L.GetEnumEntryIdentifier(ConditionCode.GE, CompDescription), "Signed >= (N == V)" },
        { L.GetEnumEntryIdentifier(ConditionCode.GT, CompDescription), "Signed > (Z == 0 & N == V)" },
        { L.GetEnumEntryIdentifier(ConditionCode.HI, CompDescription), "Unsigned > (C == 1 & Z == 0)" },
        { L.GetEnumEntryIdentifier(ConditionCode.HS, CompDescription), "Unsigned >= / Carry set (C == 1)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LE, CompDescription), "Signed <= (Z == 1 | N != V)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LO, CompDescription), "Unsigned < / Carry clear (C == 0)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LS, CompDescription), "Unsigned <= (C == 0 | Z == 1)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LT, CompDescription), "Signed < (N != V)" },
        { L.GetEnumEntryIdentifier(ConditionCode.MI, CompDescription), "Negative (N == 1)" },
        { L.GetEnumEntryIdentifier(ConditionCode.NE, CompDescription), "Not equal (Z == 0)" },
        { L.GetEnumEntryIdentifier(ConditionCode.PL, CompDescription), "Positive/zero (N == 0)" },
        { L.GetEnumEntryIdentifier(ConditionCode.VC, CompDescription), "Overflow clear (V == 0)" },
        { L.GetEnumEntryIdentifier(ConditionCode.VS, CompDescription), "Overflow set (V == 0)" },

        { $"Set flags.{CompLabel}", "-S (Set flags)" },
        { $"Set flags.{CompDescription}", "Set flags" }
    };

    public string this[string entry] => _values.TryGetValue(entry, out var val) ? val : string.Empty;

    public string this[string entry, int count] => this[entry];

    public bool HasValue(string entry) => _values.ContainsKey(entry);
}
