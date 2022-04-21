using Code4Arm.LanguageServer.CodeAnalysis.Models;

namespace Code4Arm.LanguageServer.Models;

public class LanguageServerOptions
{
    public bool ShowCodeLens { get; set; } = true;
    public string InstructionFilter { get; set; } = "Basic";
    public string[] InstructionBlacklist { get; set; } = Array.Empty<string>();
    public bool ShowUncommonMnemonicVariants { get; set; } = false;
    public bool ShowSimdInstructions { get; set; } = true;

    public InstructionVariantFlag Flag =>
        this.InstructionFilter switch
        {
            "Basic" => InstructionVariantFlag.UncommonInstruction | InstructionVariantFlag.AdvancedInstruction,
            "Uncommon" => InstructionVariantFlag.AdvancedInstruction,
            "Advanced" => InstructionVariantFlag.NoFlags,
            _ => InstructionVariantFlag.NoFlags
        }
        | (this.ShowSimdInstructions ? InstructionVariantFlag.NoFlags : InstructionVariantFlag.Simd)
        | (this.ShowUncommonMnemonicVariants ? InstructionVariantFlag.NoFlags : InstructionVariantFlag.UncommonVariant);
}