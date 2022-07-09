// InstructionList.cs
// Author: Ondřej Ondryáš

using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;

namespace GrammarMaker;

public class InstructionList
{
    private static Regex _lineRegex = new(
        @"<a href=""(.*\.html)"">(.*?)(?:\s\(.*?\))?<\/a>[:\n\s]*(.*?)(?:\.<\/span>|:|\s\()",
        RegexOptions.Compiled);

    public static async Task MakeInstructionList()
    {
        var parsed = await ParseInstructions(Program.IndexFile);
        parsed.AddRange(await ParseInstructions(Program.FpIndexFile));
        parsed.RemoveAt(0); // Proprietary Notice

        // NOT S: MLS, MRS, SRS

        var instructionGroups = parsed.GroupBy(i => i.Description);
        var target = new Dictionary<string, InstructionDefinitionModel>();

        foreach (var group in instructionGroups)
        {
            var desc = group.Key;
            var groupInstructions = group.ToList();
            var mnemonics = groupInstructions.Select(i => i.Name).ToList();
            var lp = Utils.FindLongestPrefix(mnemonics);

            if (!target.TryGetValue(lp, out var defModel))
                target.Add(lp, defModel = new InstructionDefinitionModel
                {
                    Name = desc,
                    VariantModels = new List<InstructionVariantModel>()
                });

            var linkGroups = groupInstructions.GroupBy(i => i.Link);
            foreach (var linkGroup in linkGroups)
            {
                var groupContents = linkGroup.ToList();
                if (groupContents.Count == 2 && groupContents[1].Name == groupContents[0].Name + "S")
                {
                    defModel.VariantModels.AddRange(MakeVariantModel(groupContents[0].Name + "<SCQ>", linkGroup.Key));
                }
                else
                {
                    foreach (var instructionLine in groupContents)
                    {
                        defModel.VariantModels.AddRange(MakeVariantModel(instructionLine.Name + "<CQ>", linkGroup.Key));
                    }
                }
            }
        }

        var settings = new JsonSerializerSettings()
        {
            NullValueHandling = NullValueHandling.Ignore
        };
        await File.WriteAllTextAsync("instructionList.json",
            JsonConvert.SerializeObject(target, Formatting.Indented, settings), Encoding.UTF8);
    }

    private static async Task<List<InstructionLine>> ParseInstructions(string filePath)
    {
        var file = await File.ReadAllTextAsync(filePath);
        var matches = _lineRegex.Matches(file);

        var ret = new List<InstructionLine>();
        foreach (Match match in matches)
        {
            var mnemonics = match.Groups[2].Value;
            var link = match.Groups[1].Value;
            var desc = match.Groups[3].Value;

            if (mnemonics == "FLDM*X")
            {
                ret.Add(new InstructionLine("FLDMDBX", link, desc));
                ret.Add(new InstructionLine("FLDMIAX", link, desc));

                continue;
            }

            if (mnemonics.Contains(','))
            {
                var actualMnemonics = mnemonics.Split(", ");
                ret.AddRange(actualMnemonics.Select(m => new InstructionLine(m, link, desc)));

                continue;
            }

            ret.Add(new InstructionLine(mnemonics, link, desc));
        }

        return ret;
    }

    private static string RemoveHtml(string docLink)
        => docLink[..docLink.IndexOf(".html", StringComparison.Ordinal)];

    private static IEnumerable<InstructionVariantModel> MakeVariantModel(string def, string docLink)
    {
        var defs = new List<string[]>(2);
        var dl = RemoveHtml(docLink);

        if (dl.EndsWith("_r"))
        {
            defs.Add(new[] { def, "<?Rd>", "<Rn>", "<Rm>", "<?SHI>" });
            defs.Add(new[] { def, "<?Rd>", "<Rn>", "<Rm>", "<RRX>" });
        }
        else if (dl.EndsWith("_rr"))
        {
            defs.Add(new[] { def, "<?Rd>", "<Rn>", "<Rm>", "<SHR>" });
        }
        else if (dl.EndsWith("_i"))
        {
            defs.Add(new[] { def, "<?Rd>", "<Rn>", "<Ic>" });
        }
        else
        {
            defs.Add(new[] { def });
        }

        return defs.Select(d => new InstructionVariantModel()
        {
            Definition = d,
            Documentation = dl,
            DescriptionIndex = 0,
            Priority = 0
        });
    }

    private record InstructionLine(string Name, string Link, string Description)
    {
    }
}

internal class InstructionDefinitionModel
{
    [JsonProperty(Required = Required.Always)]
    public string Name { get; init; } = null!;

    [JsonProperty("variants", Required = Required.Always)]
    public List<InstructionVariantModel> VariantModels { get; init; } = null!;
}

internal class InstructionVariantModel
{
    [JsonProperty("asm", Required = Required.Always)]
    public string[] Definition { get; init; } = null!;

    [JsonProperty("doc", Required = Required.Always)]
    public string Documentation { get; init; } = null!;

    [JsonProperty("docVariants")] public Dictionary<string, string>? DocumentationVariants { get; init; }

    [JsonProperty("simd")] public string[][]? SimdDataTypes { get; init; }

    [JsonProperty("desc")] public int DescriptionIndex { get; init; }
    [JsonProperty("prio")] public int Priority { get; init; }

    [JsonProperty("flags", DefaultValueHandling = DefaultValueHandling.IgnoreAndPopulate)]
    public int Flags { get; init; }

    [JsonProperty("symbolsDesc")] public Dictionary<string, int>? SymbolDescriptionsIndices { get; init; }
}