// InstructionVariant.cs
// Author: Ondřej Ondryáš

namespace Armfors.LanguageServer.CodeAnalysis.Models;

public class InstructionVariant
{
    public bool HasSetFlagsVariant { get; }
    public bool CanBeConditional { get; }

    public bool IsVector { get; }
    public string Mnemonic { get; }
    public bool HasOperands { get; } // TODO
    public InstructionSize? ForcedSize { get; }


    public InstructionVariant(string mnemonic, bool operands, bool cbc, bool hs)
    {
        this.HasSetFlagsVariant = hs;
        this.CanBeConditional = cbc;
        this.Mnemonic = mnemonic;
        this.HasOperands = operands;
        this.ForcedSize = null;
        this.IsVector = false;
    }

    public bool IsVectorDataTypeAllowed(int specifierIndex, VectorDataType type)
    {
        // TODO
        return false;
    }

    public IEnumerable<VectorDataType> GetPossibleVectorDataTypes(int specifierIndex)
    {
        // TODO
        return Enumerable.Empty<VectorDataType>();
    }
}
