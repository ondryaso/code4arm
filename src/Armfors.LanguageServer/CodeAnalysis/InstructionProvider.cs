using System.Collections.Immutable;
using System.Text.RegularExpressions;
using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Extensions;
using Armfors.LanguageServer.Services.Abstractions;
using Newtonsoft.Json;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.CodeAnalysis;

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
    [JsonProperty("flags")] public int Flags { get; init; }
    [JsonProperty("symbolsDesc")] public Dictionary<string, int>? SymbolDescriptionsIndices { get; init; }

    public InstructionVariantModel CloneForDefinitionVariant()
    {
        var ret = new InstructionVariantModel()
        {
            Definition = new string[this.Definition.Length],
            Documentation = this.Documentation,
            DocumentationVariants = this.DocumentationVariants,
            SimdDataTypes = this.SimdDataTypes,
            DescriptionIndex = this.DescriptionIndex,
            Priority = this.Priority,
            Flags = this.Flags,
            SymbolDescriptionsIndices = this.SymbolDescriptionsIndices
        };

        Array.Copy(this.Definition, ret.Definition, this.Definition.Length);
        return ret;
    }
}

internal class InstructionDefinition
{
    public string Name { get; init; }
    public List<InstructionVariant> Variants { get; } = new();
}

public class InstructionProvider : IInstructionProvider, IOperandAnalyserProvider, IInstructionValidatorProvider,
    IInstructionDocumentationProvider
{
    private readonly string _definitionPath;

    private Dictionary<string, InstructionDefinition>? _definitions;

    private List<InstructionVariant>? _allVariants;

    public InstructionProvider()
    {
        // TODO: Where do I want to get the definition file from?
        _definitionPath = "instruction_defs.json";
    }

    private void EnsureLoaded()
    {
        if (_definitions != null)
            return;

        using var stream = File.OpenText(_definitionPath);
        using var jsonReader = new JsonTextReader(stream);
        var serializer = new JsonSerializer();
        var rawData = serializer.Deserialize<Dictionary<string, InstructionDefinitionModel>?>(jsonReader);

        if (rawData == null)
            throw new Exception();

        _definitions = new Dictionary<string, InstructionDefinition>();
        _allVariants = new List<InstructionVariant>();

        foreach (var (mnemonic, model) in rawData)
        {
            foreach (var m in model.VariantModels)
            {
                this.ExpandDefinition(mnemonic, model, m);
            }
        }

        // TODO: handle failures
    }

    private Regex _symbolRegex = new(@"<(?<optional>\??)(?<symbol>\w*?)>", RegexOptions.Compiled);

    // Start with a <
    // Match O:... (group var is the whole thing, then there are the parts in varA, varB, varC)
    // If O:... was matched, match the next <, otherwise match nothing
    // Match optional S/C/Q (groups S, C, Q) and >
    // Match optional {<c>} and {<q>} (groups C2, Q2)
    private Regex _typeVariantExpansionRegex =
        new(
            @"<(?<var>O:(?<varA>\w+?)\|(?:(?<varB>\w+?)\|)*(?<varC>\w+?)>)?((?(var)<|)(?<S>S)?(?<C>C)?(?<Q>Q)?>)?(?<C2>{<c>})?(?<Q2>{<q>})?",
            RegexOptions.Compiled);

    private struct ExpansionContext
    {
        public InstructionDefinitionModel DefinitionModel;
        public InstructionVariantModel VariantModel;

        public bool HasSetFlags = false;
        public bool HasConditionCode = false;
        public bool HasSizeQualifier = false;
        public bool HasOperands = false;
        public InstructionSize? ForceSize = null;

        public ExpansionContext(InstructionDefinitionModel definitionModel, InstructionVariantModel variantModel)
        {
            DefinitionModel = definitionModel;
            VariantModel = variantModel;
        }
    }

    private void ExpandDefinition(string mnemonic, InstructionDefinitionModel definitionModel,
        InstructionVariantModel variantModel)
    {
        if (variantModel.Definition.Length == 0)
            return;

        var i = 0;
        foreach (var def in variantModel.Definition)
        {
            if (def == "<AI>")
            {
                var copyOffset = variantModel.CloneForDefinitionVariant();
                var copyPre = variantModel.CloneForDefinitionVariant();
                var copyPost = variantModel.CloneForDefinitionVariant();

                copyOffset.Definition[i] = "AIo";
                copyPre.Definition[i] = "AIp";
                copyPost.Definition[i] = "AI!";

                this.ExpandDefinition(mnemonic, definitionModel, copyOffset);
                this.ExpandDefinition(mnemonic, definitionModel, copyPre);
                this.ExpandDefinition(mnemonic, definitionModel, copyPost);

                return;
            }

            if (def == "<AR>")
            {
                var copyOffset = variantModel.CloneForDefinitionVariant();
                var copyPre = variantModel.CloneForDefinitionVariant();
                var copyPost = variantModel.CloneForDefinitionVariant();

                copyOffset.Definition[i] = "ARo";
                copyPre.Definition[i] = "ARp";
                copyPost.Definition[i] = "AR!";

                this.ExpandDefinition(mnemonic, definitionModel, copyOffset);
                this.ExpandDefinition(mnemonic, definitionModel, copyPre);
                this.ExpandDefinition(mnemonic, definitionModel, copyPost);

                return;
            }

            i++;
        }

        var mnemonicDef = variantModel.Definition[0];
        var match = _typeVariantExpansionRegex.Match(mnemonicDef);

        var makeDefaultVariant = true;

        var ctx = new ExpansionContext(definitionModel, variantModel)
        {
            HasOperands = variantModel.Definition.Length > 1
        };

        if (match.Success)
        {
            ctx.HasSetFlags = match.Groups["S"].Success;
            ctx.HasConditionCode = match.Groups["C"].Success || match.Groups["C2"].Success;
            ctx.HasSizeQualifier = match.Groups["Q"].Success || match.Groups["Q2"].Success;

            if (mnemonicDef.Length > (match.Index + match.Length))
            {
                var mnemonicTail = mnemonicDef[(match.Index + match.Length)..].TrimEnd();
                if (mnemonicTail == ".W")
                {
                    ctx.ForceSize = InstructionSize.W;
                }
                else if (mnemonicTail == ".N")
                {
                    ctx.ForceSize = InstructionSize.N;
                }
                else
                {
                    throw new Exception($"Invalid mnemonic: {mnemonicDef}");
                }
            }

            if (ctx.ForceSize.HasValue && ctx.HasSizeQualifier)
            {
                throw new Exception($"Mnemonic {mnemonicDef} has both <q> and a forced size qualifier.");
            }

            mnemonicDef = mnemonicDef[..match.Index];
            if (match.Groups["var"].Success)
            {
                makeDefaultVariant = false;

                // Has variants <O:x|y|z...>
                var allVariants = match.Groups["varA"].Captures.Concat(match.Groups["varB"].Captures)
                    .Concat(match.Groups["varC"].Captures).Select(c => c.Value);

                foreach (var variant in allVariants)
                {
                    if (variant == "x")
                    {
                        makeDefaultVariant = true;
                    }
                    else
                    {
                        this.MakeVariant(mnemonicDef + variant, ctx);
                    }
                }
            }
        }

        if (makeDefaultVariant)
        {
            if (mnemonicDef.EndsWith(".W"))
            {
                ctx.ForceSize = InstructionSize.W;
            }
            else if (mnemonicDef.EndsWith(".N"))
            {
                ctx.ForceSize = InstructionSize.N;
            }

            this.MakeVariant(mnemonicDef, ctx);
        }
    }

    private void MakeVariant(string variantMnemonic, ExpansionContext ctx)
    {
        if (!_definitions!.TryGetValue(variantMnemonic, out var definition))
        {
            definition = new InstructionDefinition() { Name = ctx.DefinitionModel.Name };
            _definitions.Add(variantMnemonic, definition);
        }

        var variant = new InstructionVariant(variantMnemonic, ctx.HasOperands, ctx.VariantModel, this)
        {
            HasSetFlagsVariant = ctx.HasSetFlags,
            CanBeConditional = ctx.HasConditionCode,
            ForcedSize = ctx.ForceSize,
            IsVector = variantMnemonic[0] == 'V'
        };

        definition.Variants.Add(variant);
        _allVariants!.Add(variant);
    }

    public IEnumerable<OperandDescriptor> GetOperands(InstructionVariant instructionVariant)
    {
        if (!instructionVariant.HasOperands)
            return Enumerable.Empty<OperandDescriptor>();

        var operandDefinitions = instructionVariant.Model.Definition[1..];

        var ret = new List<OperandDescriptor>(operandDefinitions.Length);

        foreach (var operandDefinition in operandDefinitions)
        {
            var matches = _symbolRegex.Matches(operandDefinition);
            if (matches.Count == 0)
            {
                ret.Add(new OperandDescriptor(instructionVariant, operandDefinition));
                continue;
            }

            if (matches.Count == 1)
            {
                ret.Add(this.MakeSingleSymbolOperand(instructionVariant, matches[0]));
                continue;
            }

            var newOperand = this.MakeComposedOperand(instructionVariant, matches, operandDefinition);
            ret.Add(newOperand);
        }

        return ret;
    }

    private readonly struct OperandRegexPart
    {
        public readonly int Index;
        public readonly string Regex;
        public readonly ImmutableDictionary<int, OperandToken> Tokens;

        public OperandRegexPart(int index, string regex, ImmutableDictionary<int, OperandToken> tokens)
        {
            Index = index;
            Regex = regex;
            Tokens = tokens;
        }
    }

    // Match things like <Rd>, <Rdm>, <Rt2>, <RdHi>; register mask may be specified by :reg|reg or :!reg|reg (blacklist)
    // e.g. <Rd:0|10|2|LR> or <Rs:!PC>.
    private readonly Regex _regRegex =
        new(@"^(?<name>R\w{1,3})(?::(?<reverse>!)?(?:(?<reg>1[543210]|[9876543210]|PC|LR)(?(?=.)\||))+)?$",
            RegexOptions.Compiled);

    // Match <Ic> (modified const.), <I[imm size]> (imm) or <I[imm size>D> (imm /4).
    private readonly Regex _immRegex = new(@"^I(?:(c)|(?:(\d\d?)([dD])?))$", RegexOptions.Compiled);

    // Like _regRegex but for shifts. Used as <SHI> for imm shift or <SHR> for register shift
    private readonly Regex _shiftRegex = new(
        @"^SH(?<shtype>[IR])(?::(?<reverse>!)?(?:(?<shift>LSL|LSR|ASR|ROR)(?(?=.)\||))+)?$",
        RegexOptions.Compiled);

    // Like _regRegex but for SIMD S* and D* registers (0–31); <Sd[]> can be used for denoting indexed register
    private readonly Regex _sdRegRegex =
        new(
            @"^(?<name>[SD]\w{1,3})(?<indexed>\[\])?(?::(?<reverse>!)?(?:(?<reg>3[10]|[21]?[9876543210])(?(?=.)\||))+)?$",
            RegexOptions.Compiled);

    // Like _sdRegRegex but for SIMD Q* registers (0–15)
    private readonly Regex _qRegRegex =
        new(@"^(?<name>Q\w{1,3})(?<indexed>\[\])?(?::(?<reverse>!)?(?:(?<reg>1[543210]|[9876543210])(?(?=.)\||))+)?$",
            RegexOptions.Compiled);

    // Like _regRegex but supports +PC to denote RegisterListWithPC
    private readonly Regex _registerListRegex = new(
        @"^reglist(?::(?<reverse>!)?(?:(?<reg>1[543210]|[9876543210]|\+PC|PC|LR)(?(?=.)\||))+)?$",
        RegexOptions.Compiled);

    private const string ImmTargetRegex = "#?([+-]?[0-9]+)";
    private const string RegisterTargetRegex = "(R(?:1[543210]|[9876543210])|LR|PC|SP)";
    private const string LabelTargetRegex = @"(?:\""(?<1>[\w.$ ]+)\""|(?<1>[\w.$]+))";

    private const string RegListRegex =
        @"\G(?<hasMore>{)?((?<match>(?<rs>R(?:1[543210]|[9876543210])|LR|PC|SP)(?:\s?(?<hasMore>\-)\s?(?<re>R(?:1[543210]|[9876543210])|LR|PC|SP))*)(?(?=[\w,])(?<hasMore>,)\s?))*(?(hasMore)})";

    private OperandDescriptor MakeSingleSymbolOperand(InstructionVariant mnemonic, Match match)
    {
        var symbol = match.Groups["symbol"].Value;
        var optional = match.Groups["optional"].Length == 1;

        switch (symbol[0])
        {
            case 'R':
                if (symbol == "RRX")
                    return this.MakeRrxOperand(mnemonic, optional);
                else
                    return this.MakeRegisterOperand(_regRegex.Match(symbol), mnemonic, optional);
            case 'I':
                return this.MakeImmediateOperand(_immRegex.Match(symbol), mnemonic, optional);
            case 'S':
                if (symbol[1] == 'H')
                    return this.MakeShiftOperand(_shiftRegex.Match(symbol), mnemonic, optional);
                else
                    return this.MakeSRegisterOperand(_sdRegRegex.Match(symbol), mnemonic, optional);
            case 'A':
                if (symbol[1] == 'I')
                    return this.MakeImmediateAddressingOperand(symbol, mnemonic, optional);
                else
                    return this.MakeRegisterAddressingOperand(symbol, mnemonic, optional);
            case 'L':
                return this.MakeLabelOperand(mnemonic, optional);
            case 'D':
                return this.MakeSRegisterOperand(_sdRegRegex.Match(symbol), mnemonic, optional);
            case 'Q':
                return this.MakeQRegisterOperand(_qRegRegex.Match(symbol), mnemonic, optional);
            case 'r':
                return this.MakeRegisterListOperand(_registerListRegex.Match(symbol), mnemonic, optional);
            default:
                throw new Exception($"Unsupported definition symbol: <{symbol}>");
        }
    }

    private OperandDescriptor MakeRegisterOperand(Match registerMatch, InstructionVariant mnemonic, bool optional)
    {
        var mask = RegisterExtensions.All;
        if (registerMatch.Groups["reg"].Success)
        {
            mask = 0;
            var maskValues = registerMatch.Groups["reg"].Captures.Select(c => c.Value).Distinct();
            foreach (var maskValue in maskValues)
            {
                if (int.TryParse(maskValue, out var maskNumber))
                {
                    mask |= (Register)(1 << maskNumber);
                }
                else if (EnumExtensions.TryParseName(maskValue, out Register maskRegValue))
                {
                    mask |= maskRegValue;
                }
            }

            if (registerMatch.Groups["reverse"].Success)
            {
                mask = ~mask;
            }
        }

        var descriptor = new OperandDescriptor(mnemonic, $@"\G{RegisterTargetRegex}",
            OperandType.Register, optional,
            (0, 1,
                new OperandToken(OperandTokenType.Register, registerMatch.Groups["name"].Value)
                    { RegisterMask = mask }));

        return descriptor;
    }

    private OperandDescriptor MakeImmediateOperand(Match immediateMatch, InstructionVariant mnemonic, bool optional)
    {
        const string regex = $@"\G{ImmTargetRegex}";

        if (immediateMatch.Groups[1].Length > 0)
        {
            return new OperandDescriptor(mnemonic, regex, OperandType.ImmediateConstant,
                OperandTokenType.ImmediateConstant,
                "const", optional: optional);
        }

        var size = int.Parse(immediateMatch.Groups[2].Value);
        var isDiv4 = immediateMatch.Groups[3].Length > 0;
        var token = new OperandToken(OperandTokenType.Immediate, "imm" + size)
        {
            ImmediateSize = size,
            IsImmediateDiv4 = isDiv4
        };

        return new OperandDescriptor(mnemonic, regex, isDiv4 ? OperandType.ImmediateDiv4 : OperandType.Immediate,
            optional, (0, 1, token));
    }

    private OperandDescriptor MakeShiftOperand(Match shiftMatch, InstructionVariant mnemonic, bool optional)
    {
        var isImmediateShift = shiftMatch.Groups["shtype"].Value == "I";
        ShiftType[]? mask = null;

        if (shiftMatch.Groups["shift"].Captures.Count > 0)
        {
            var shiftTypes = shiftMatch.Groups["shift"].Captures.Distinct()
                .Select(c => (EnumExtensions.TryParseName(c.Value, out ShiftType s), s))
                .Where(c => c.Item1).Select(c => c.s);

            if (shiftMatch.Groups["reverse"].Length > 0)
            {
                mask = Enum.GetValues<ShiftType>().Except(shiftTypes).ToArray();
            }
            else
            {
                mask = shiftTypes.ToArray();
            }
        }

        if (isImmediateShift)
        {
            return new OperandDescriptor(mnemonic, new[] { @"\G(LS[RL]|ASR|ROR)", " #?([+-]?[0-9]+)" },
                OperandType.Shift,
                optional, (0, 1, new OperandToken(OperandTokenType.ShiftType, "shift") { AllowedShiftTypes = mask }),
                (1, 1, new OperandToken(OperandTokenType.ImmediateShift, "imm")));
        }
        else
        {
            return new OperandDescriptor(mnemonic, new[] { @"\G(LS[RL]|ASR|ROR)", $@"\G {RegisterTargetRegex}" },
                OperandType.Shift,
                optional, (0, 1, new OperandToken(OperandTokenType.ShiftType, "shift") { AllowedShiftTypes = mask }),
                (1, 1, new OperandToken(OperandTokenType.Register, "Rs")));
        }
    }

    private OperandDescriptor MakeImmediateAddressingOperand(string symbol, InstructionVariant mnemonic, bool optional)
    {
        return Dummy(mnemonic);
    }

    private OperandDescriptor MakeRegisterAddressingOperand(string symbol, InstructionVariant mnemonic, bool optional)
    {
        return Dummy(mnemonic);
    }

    private OperandDescriptor MakeLabelOperand(InstructionVariant mnemonic, bool optional)
    {
        return new OperandDescriptor(mnemonic, $@"\G{LabelTargetRegex}", OperandType.Label, OperandTokenType.Label,
            "label", 1, optional);
    }

    private OperandDescriptor MakeRegisterListOperand(Match registerListMatch, InstructionVariant mnemonic,
        bool optional)
    {
        return new OperandDescriptor(mnemonic, RegListRegex, OperandType.RegisterList, optional);
    }

    private OperandDescriptor MakeRrxOperand(InstructionVariant mnemonic, bool optional)
    {
        return new OperandDescriptor(mnemonic, @"\GRRX", OperandType.RRX, optional);
    }

    private OperandDescriptor MakeSRegisterOperand(Match registerMatch, InstructionVariant mnemonic, bool optional)
    {
        return Dummy(mnemonic);
    }

    private OperandDescriptor MakeQRegisterOperand(Match registerMatch, InstructionVariant mnemonic, bool optional)
    {
        return Dummy(mnemonic);
    }

    private static OperandDescriptor Dummy(InstructionVariant mnemonic)
    {
        return new OperandDescriptor(mnemonic, "x");
    }

    private OperandDescriptor MakeComposedOperand(InstructionVariant instructionVariant, MatchCollection matches,
        string operandDefinition)
    {
        OperandType? operandType = null;
        var operandOptional = false;
        var regexIndex = 0;
        var regexParts = new List<OperandRegexPart>();

        for (var matchI = 0; matchI < matches.Count; matchI++)
        {
            var match = matches[matchI];
            var tokenSymbol = match.Groups["symbol"].Value;
            var tokenOptional = match.Groups["optional"].Length == 1;

            if (tokenSymbol == "_")
            {
                operandOptional = tokenOptional;
                continue;
            }

            if (!operandType.HasValue)
            {
                operandType = this.DetermineOperandType(tokenSymbol);
            }

            regexParts.AddRange(this.MakeRegexesForSymbol(tokenSymbol, tokenOptional, ref regexIndex));

            // Add following literal
            var endPos = match.Index + match.Length;
            var nextStart = matchI == (matches.Count - 1) ? operandDefinition.Length : matches[matchI + 1].Index;
            if (nextStart != endPos)
            {
                regexParts.Add(new OperandRegexPart(regexIndex++, "\\G" + operandDefinition[endPos..nextStart],
                    ImmutableDictionary<int, OperandToken>.Empty));
            }
        }

        var newOperand = new OperandDescriptor(instructionVariant, regexParts.Select(r => r.Regex),
            operandType ?? OperandType.Literal, operandOptional,
            regexParts.ToImmutableDictionary(k => k.Index, k => k.Tokens));

        return newOperand;
    }

    private OperandType DetermineOperandType(string firstSymbol)
    {
        return firstSymbol switch
        {
            _ when firstSymbol.StartsWith("R") => OperandType.Register,
            _ when firstSymbol.StartsWith("Ic") => OperandType.ImmediateConstant,
            _ when firstSymbol.StartsWith("ID") => OperandType.ImmediateDiv4,
            _ when firstSymbol.StartsWith("I") => OperandType.Immediate,
            _ when firstSymbol.StartsWith("SH") => OperandType.Shift,
            "AI" => OperandType.ImmediateAddressing,
            "AR" => OperandType.RegisterAddressing
            // TODO (maybe)
        };
    }

    private IEnumerable<OperandRegexPart> MakeRegexesForSymbol(string symbol, bool optional, ref int startIndex)
    {
        // TODO (maybe)
        return Enumerable.Empty<OperandRegexPart>();
    }

    public Task<List<InstructionVariant>> GetAllInstructions()
    {
        this.EnsureLoaded();
        return Task.FromResult(_allVariants!);
    }

    public Task<List<InstructionVariant>> FindMatchingInstructions(string line)
    {
        this.EnsureLoaded();

        return Task.FromResult(_allVariants!
            .Where(m => m.Mnemonic.StartsWith(line, StringComparison.InvariantCultureIgnoreCase)).ToList());
    }

    public Task<List<InstructionVariant>?> GetVariants(string mnemonic,
        InstructionVariantFlag exclude = InstructionVariantFlag.NoFlags)
    {
        this.EnsureLoaded();
        mnemonic = mnemonic.ToUpperInvariant();

        if (!_definitions!.TryGetValue(mnemonic, out var model))
            return Task.FromResult<List<InstructionVariant>?>(null);

        return Task.FromResult<List<InstructionVariant>?>(model.Variants
            .Where(m => (m.VariantFlags & exclude) == 0)
            .ToList());
    }

    public IOperandAnalyser For(OperandDescriptor descriptor)
    {
        // TODO: Cache
        return new BasicOperandAnalyser(descriptor);
    }

    public IInstructionValidator? For(InstructionVariant instructionVariant)
    {
        return null;
    }

    public string InstructionDetail(InstructionVariant instructionVariant)
    {
        this.EnsureLoaded();
        if (_definitions?.TryGetValue(instructionVariant.Mnemonic, out var model) ?? false)
        {
            return model.Name;
        }

        return string.Empty;
    }

    public MarkupContent? InstructionEntry(InstructionVariant instructionVariant)
    {
        return new MarkupContent() { Kind = MarkupKind.Markdown, Value = "test - instruction" };
    }

    public MarkupContent? InstructionOperandEntry(InstructionVariant instructionVariant, string tokenName)
    {
        return new MarkupContent() { Kind = MarkupKind.Markdown, Value = "test - op" };
    }
}
