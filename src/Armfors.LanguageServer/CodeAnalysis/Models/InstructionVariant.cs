// InstructionVariant.cs
// Author: Ondřej Ondryáš

using System.Collections.Immutable;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

public class InstructionVariant : IEquatable<InstructionVariant>, IComparable<InstructionVariant>
{
    public bool HasSetFlagsVariant { get; }
    public bool CanBeConditional { get; }

    public bool IsVector { get; }
    public string Mnemonic { get; }
    public bool HasOperands => !this.Operands.IsEmpty;
    public InstructionSize? ForcedSize { get; }

    public InstructionVariantFlag VariantFlags { get; init; } = InstructionVariantFlag.NoFlags;
    public int VariantPriority { get; init; } = 0;

    public ImmutableList<OperandDescriptor> Operands { get; }

    private readonly int _operandsHashCode;

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
            _operandsHashCode = HashCode.Combine(_operandsHashCode, descriptor.GetHashCode());
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
        if (specifierIndex is not (0 or 1)) return Enumerable.Empty<VectorDataType>();
        return new[]
        {
            VectorDataType.Any16, VectorDataType.F16, VectorDataType.I16,
            VectorDataType.U16, VectorDataType.S16, VectorDataType.P16
        };
    }

    public bool Equals(InstructionVariant? other)
    {
        if (ReferenceEquals(null, other))
            return false;
        if (ReferenceEquals(this, other))
            return true;

        return this.Mnemonic == other.Mnemonic &&
               this.VariantFlags == other.VariantFlags &&
               this.Operands.SequenceEqual(other.Operands);
    }

    public int CompareTo(InstructionVariant? other)
    {
        if (other == null)
            return -1;
        if (other.Mnemonic != this.Mnemonic)
            return string.Compare(other.Mnemonic, this.Mnemonic, StringComparison.Ordinal);

        return other.VariantPriority - this.VariantPriority;
    }

    public override bool Equals(object? obj)
    {
        if (ReferenceEquals(null, obj))
            return false;
        if (ReferenceEquals(this, obj))
            return true;
        if (obj.GetType() != this.GetType())
            return false;

        return this.Equals((InstructionVariant)obj);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(this.Mnemonic, this.VariantFlags, _operandsHashCode);
    }
}
