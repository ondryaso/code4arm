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


    public InstructionVariant(string mnemonic, bool operands, bool cbc, bool hs, bool v = false)
    {
        this.HasSetFlagsVariant = hs;
        this.CanBeConditional = cbc;
        this.Mnemonic = mnemonic;
        this.HasOperands = operands;
        this.ForcedSize = null;
        this.IsVector = v;
    }

    public bool IsVectorDataTypeAllowed(int specifierIndex, VectorDataType type)
    {
        // TODO
        return this.IsVector && specifierIndex is 0 or 1 && type.GetElementSize() == 16;
    }

    public IEnumerable<VectorDataType> GetPossibleVectorDataTypes(int specifierIndex)
    {
        // TODO
        if (specifierIndex is not 0 or 1) return Enumerable.Empty<VectorDataType>();
        return new[]
        {
            VectorDataType.Any16, VectorDataType.F16, VectorDataType.I16,
            VectorDataType.U16, VectorDataType.S16, VectorDataType.P16
        };
    }
}
