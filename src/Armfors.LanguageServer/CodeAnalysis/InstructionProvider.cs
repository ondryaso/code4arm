using System.Text.RegularExpressions;
using Armfors.LanguageServer.CodeAnalysis.Abstractions;
using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Services.Abstractions;
using Newtonsoft.Json;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Armfors.LanguageServer.CodeAnalysis;

internal class StringToUpperConverter : JsonConverter
{
    public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
    {
        throw new NotImplementedException();
    }

    public override object? ReadJson(JsonReader reader, Type objectType, object existingValue,
        JsonSerializer serializer)
    {
        if (existingValue is string s)
            return s.ToUpperInvariant();

        return null;
    }

    public override bool CanConvert(Type objectType)
    {
        return objectType == typeof(string);
    }
}

internal class InstructionDefinitionModel
{
    [JsonProperty(Required = Required.Always)]
    [JsonConverter(typeof(StringToUpperConverter))]
    public string Name { get; init; } = null!;

    [JsonProperty(Required = Required.Always)]
    public List<InstructionVariantModel> VariantModels { get; init; } = null!;
}

internal class InstructionVariantModel
{
    [JsonProperty("asm", Required = Required.Always)]
    public string DefinitionLine { get; init; } = null!;

    [JsonProperty("doc", Required = Required.Always)]
    public string Documentation { get; init; } = null!;

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
        _definitionPath = "instruction_definitions.json";
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
    private Regex _typeVariantExpansionRegex = new(@"(<O:(\w+?)\|(?:(\w+?)\|)*(\w+?)>)?(<(S)?(C)?(Q)?>)?({<c>})?({<q>})?");

    private void ExpandDefinition(string mnemonic, InstructionDefinitionModel definitionModel,
        InstructionVariantModel variantModel)
    {
        var def = variantModel.DefinitionLine.Trim();
        var defSpaceIndex = def.IndexOf(' ');
        var hasOperands = defSpaceIndex == -1;
        var mnemonicPart = def[..defSpaceIndex];

        Match? match = null;
        mnemonicPart = _typeVariantExpansionRegex.Replace(mnemonicPart, (m =>
        {
            match = m;
            return string.Empty;
        }), 1);
        
        
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
        if (_rawDefinitions?.TryGetValue(instructionVariant.Mnemonic, out var model) ?? false)
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