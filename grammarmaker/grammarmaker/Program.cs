using System.Text;
using System.Text.RegularExpressions;

const string index =
    @"/home/ondryaso/.config/Code/User/globalStorage/ondryaso.code4arm/docs/ISA_AArch32_xml_v88A-2021-12/xhtml/index.html";
const string fpIndex =
    @"/home/ondryaso/.config/Code/User/globalStorage/ondryaso.code4arm/docs/ISA_AArch32_xml_v88A-2021-12/xhtml/fpsimdindex.html";

var basel = await GetInstructions(index);
Group(basel, "LDM");
Group(basel, "LDR");
Group(basel, "LDA");
Group(basel, "STM");
Group(basel, "STR");

var ldm = basel.Find(i => i.Name == "LDM");
if (ldm != null)
{
    ldm.Variants!.Add("FA");
    ldm.Variants.Add("EA");
    ldm.Variants.Add("ED");
}

var s = basel.FindAll(i => i.Name.EndsWith("S") && i.Variants == null);
foreach (var si in s)
{
    InstructionType? b;
    if ((b = basel.Find(i => i.Name == si.Name[0..^1])) != null)
    {
        basel.Remove(si);
        b.SetFlags = true;
    }
}

var sb = new StringBuilder();
sb.Append(@"\\b(?i)(?:");
foreach (var i in basel.OrderByDescending(b => b.Name.Length))
{
    sb.Append(i.Name);
    if (i.Variants != null)
    {
        sb.Append("(?:");
        foreach (var variant in i.Variants.Distinct())
        {
            sb.Append(variant);
            sb.Append("|");
        }

        sb.Length--;
        sb.Append(")?");
    }

    if (i.SetFlags)
    {
        sb.Append("S?");
    }

    sb.Append("|");
}

sb.Length--;
sb.Append(
    @"|SMLA(?:BB|BT|TB|TT|DX|D|LS|L|LBB|LBT|LTB|LTT|LD|LDX|WB|WT)|SMUL(?:BB|BT|TB|TT|LS|L|WT|WB)|SMML(?:AR|A|SR|S))(\\w{2})?(?-i)\\b");
Console.WriteLine(sb.ToString());

var simd = await GetSimdInstructions(fpIndex);
sb.Clear();
sb.AppendLine();
sb.Append(@"\\b(?i)(?:");

foreach (var i in simd)
{
    sb.Append(i.Name);
    if (i.Variants != null)
    {
        sb.Append("(?:");
        foreach (var variant in i.Variants.Distinct())
        {
            sb.Append(variant);
            sb.Append("|");
        }

        sb.Length--;
        sb.Append(i.SetFlags ? ")?" : ")");
    }

    sb.Append("|");
}

sb.Length--;
sb.Append(
    @")(\\w{2})?(?:\\.([IPSU]?8|[IPSUF]?16|[ISUF]?32|[IPSU]?64))?(?-i)\\b");

Console.WriteLine(sb.ToString());

return 0;

void Group(List<InstructionType> list, string mnemonic)
{
    var b = list.Find(i => i.Name == mnemonic);

    if (b == null)
        throw new Exception();

    var sub = list.FindAll(i => i.Name.StartsWith(mnemonic) && i.Name != mnemonic);
    foreach (var i in sub)
    {
        if (i.SetFlags == b.SetFlags)
        {
            list.Remove(i);
            b.Variants ??= new List<string>();
            b.Variants.Add(i.Name[b.Name.Length..]);
        }
    }
}

async Task<List<InstructionType>> GetInstructions(string file)
{
    var regex = new Regex(@"<a href="".*\.html"">(.*)<\/a>[:\n\s]");

    var contents = await File.ReadAllTextAsync(file);
    var ret = new Dictionary<string, InstructionType>();

    var matches = regex.Matches(contents);

    foreach (Match match in matches)
    {
        var name = match.Groups[1].Value;
        var specIndex = name.IndexOf(" (");
        if (specIndex != -1)
            name = name[0..specIndex];

        var nameParts = name.Split(", ");

        var baseMnemonic = nameParts[0];
        if (baseMnemonic == "CBNZ")
        {
            ret.Add("CB", new InstructionType("CB") { Variants = new List<string>() { "NZ", "Z" } });

            continue;
        }

        if (baseMnemonic.StartsWith("SMLA") || baseMnemonic.StartsWith("SMML") || baseMnemonic.StartsWith("SMUL"))
            continue;

        InstructionType t;

        if (!ret.ContainsKey(baseMnemonic))
            ret.Add(baseMnemonic, t = new InstructionType(baseMnemonic));
        else
            t = ret[baseMnemonic];

        for (var i = 1; i < nameParts.Length; i++)
        {
            if (nameParts[i].IndexOf('S') == baseMnemonic.Length)
                t.SetFlags = true;
            else
            {
                t.Variants ??= new List<string>();
                t.Variants.Add(nameParts[i][baseMnemonic.Length..]);
            }
        }
    }

    return ret.Values.ToList();
}

async Task<List<InstructionType>> GetSimdInstructions(string file)
{
    var regex = new Regex(@"<a href="".*\.html"">(.*)<\/a>[:\n\s]");
    var contents = await File.ReadAllTextAsync(file);
    var matches = regex.Matches(contents);
    var ret = new List<string>();

    foreach (Match match in matches)
    {
        var name = match.Groups[1].Value;
        var specIndex = name.IndexOf(" (");
        if (specIndex != -1)
            name = name[0..specIndex];

        if (name == "FLDM*X")
        {
            ret.Add("FLDMDBX");
            ret.Add("FLDMIAX");

            continue;
        }

        var nameParts = name.Split(", ");
        ret.AddRange(nameParts);
    }

    ret = ret.Distinct().ToList();

    var longestPrefix = new Dictionary<string, string>();
    for (int i = 0; i != ret.Count; i++)
    {
        for (int j = i + 1; j != ret.Count; j++)
        {
            var common = FindLongestPrefix(ret[i], ret[j]);
            AddLongest(longestPrefix, ret[i], common);
            AddLongest(longestPrefix, ret[j], common);
        }
    }

    var groups = ret.GroupBy(x => longestPrefix[x]);

    return groups.Select(g =>
    {
        var r = new InstructionType(g.Key) { Variants = g.Select(x => x[g.Key.Length..]).ToList() };

        r.SetFlags = r.Variants.Contains(string.Empty);
        r.Variants.Remove(string.Empty);

        if (r.Variants.Count == 0)
            r.Variants = null;

        return r;
    }).OrderByDescending(i => i.Name.Length).ThenBy(i => i.Name).ToList();

    void AddLongest(IDictionary<string, string> dict, string s, string p)
    {
        string current;
        if (!dict.TryGetValue(s, out current) || p.Length > current.Length)
        {
            dict[s] = p;
        }
    }

    string FindLongestPrefix(string a, string b)
    {
        if (a.CompareTo(b) > 0)
        {
            (a, b) = (b, a);
        }

        /* find the minimum length from first
        and last string */
        int end = Math.Min(a.Length,
            b.Length);

        /* find the common prefix between the 
        first and last string */
        int i = 0;
        while (i < end && a[i] == b[i])
            i++;

        string pre = a.Substring(0, i);

        return pre;
    }
}

record InstructionType(string Name)
{
    public List<string>? Variants { get; set; }
    public bool SetFlags { get; set; }
}
