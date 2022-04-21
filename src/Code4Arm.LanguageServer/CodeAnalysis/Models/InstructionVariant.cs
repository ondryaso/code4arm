// InstructionVariant.cs
// Author: Ondřej Ondryáš

using System.Collections.Immutable;
using Code4Arm.LanguageServer.CodeAnalysis.Models.Abstractions;

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

public class InstructionVariant : IEquatable<InstructionVariant>, IComparable<InstructionVariant>
{
    public string Mnemonic { get; }
    public InstructionVariantFlag VariantFlags { get; }
    public int VariantPriority { get; }
    public bool HasOperands { get; }
    public bool HasSetFlagsVariant { get; init; }
    public bool CanBeConditional { get; init; }
    public bool IsVector { get; init; }
    public InstructionSize? ForcedSize { get; init; }

    private ImmutableList<IOperandDescriptor>? _operandDescriptors;

    internal InstructionVariantModel Model { get; }

    public ImmutableList<IOperandDescriptor> Operands =>
        _operandDescriptors ??= _provider.GetOperands(this).ToImmutableList();

    private readonly InstructionProvider _provider;

    private readonly int _hashCode;

    internal InstructionVariant(string mnemonic, bool hasOperands, InstructionVariantModel model,
        InstructionProvider provider)
    {
        this.Model = model;
        _provider = provider;

        this.Mnemonic = mnemonic;
        this.VariantFlags = (InstructionVariantFlag)model.Flags;
        this.VariantPriority = model.Priority;
        this.HasOperands = hasOperands;

        if (!hasOperands)
        {
            _operandDescriptors = ImmutableList<IOperandDescriptor>.Empty;
        }

        var hashCode = new HashCode();
        hashCode.Add(this.Mnemonic);
        hashCode.Add(this.VariantFlags);

        foreach (var item in model.Definition)
        {
            hashCode.Add(item);
        }

        _hashCode = hashCode.ToHashCode();
    }

    public bool Equals(InstructionVariant? other)
    {
        if (ReferenceEquals(null, other))
            return false;
        if (ReferenceEquals(this, other))
            return true;

        return this.Mnemonic == other.Mnemonic &&
               this.VariantFlags == other.VariantFlags &&
               this.Model.Definition.SequenceEqual(other.Model.Definition);
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
        return _hashCode;
    }
}
