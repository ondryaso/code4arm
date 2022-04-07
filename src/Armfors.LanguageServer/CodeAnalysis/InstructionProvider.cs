using System.Text.RegularExpressions;
using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
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

    private Regex _mnemonicSpecifierRegex = new(@"");
    private Regex _symbolRegex = new(@"<(\w*?)>");

    // Start with a <
    // Match O:... (group var is the whole thing, then there are the parts in varA, varB, varC)
    // If O:... was matched, match the next <, otherwise match nothing
    // Match optional S/C/Q (groups S, C, Q) and >
    // Match optional {<c>} and {<q>} (groups C2, Q2)
    private Regex _typeVariantExpansionRegex =
        new(@"<(?<var>O:(?<varA>\w+?)\|(?:(?<varB>\w+?)\|)*(?<varC>\w+?)>)?((?(var)<|)(?<S>S)?(?<C>C)?(?<Q>Q)?>)?(?<C2>{<c>})?(?<Q2>{<q>})?");

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
            definition = new InstructionDefinition() { Name = ctx.DefinitionModel.Name };

        var variant = new InstructionVariant(variantMnemonic, ctx.HasOperands, ctx.VariantModel)
        {
            HasSetFlagsVariant = ctx.HasSetFlags,
            CanBeConditional = ctx.HasConditionCode,
            ForcedSize = ctx.ForceSize,
            IsVector = variantMnemonic[0] == 'V'
        };

        definition.Variants.Add(variant);
        _allVariants!.Add(variant);
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
        return null;
    }

    public MarkupContent? InstructionOperandEntry(InstructionVariant instructionVariant, string tokenName)
    {
        return null;
    }
}
