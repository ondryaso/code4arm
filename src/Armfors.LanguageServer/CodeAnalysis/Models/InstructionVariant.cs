// InstructionVariant.cs
// Author: Ondřej Ondryáš

using System.Collections.Immutable;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

public class InstructionVariant
{
    public bool HasSetFlagsVariant { get; }
    public bool CanBeConditional { get; }

    public bool IsVector { get; }
    public string Mnemonic { get; }
    public bool HasOperands => !this.Operands.IsEmpty;
    public InstructionSize? ForcedSize { get; }

    public ImmutableList<OperandDescriptor> Operands { get; }

    public InstructionVariant(string mnemonic, bool cbc, bool hs, bool v = false,
        params OperandDescriptor[] descriptors)
    {
        this.HasSetFlagsVariant = hs;
        this.CanBeConditional = cbc;
        this.Mnemonic = mnemonic;
        this.ForcedSize = null;
        this.IsVector = v;
        this.Operands = descriptors.ToImmutableList();
        foreach (var descriptor in descriptors)
        {
            descriptor.Mnemonic = this;
        }
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
