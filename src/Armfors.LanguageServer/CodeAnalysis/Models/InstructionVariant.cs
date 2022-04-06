// InstructionVariant.cs
// Author: Ondřej Ondryáš

using System.Collections.Immutable;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

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

    private ImmutableList<OperandDescriptor>? _operandDescriptors;

    public ImmutableList<OperandDescriptor> Operands => _operandDescriptors ??= this.ParseOperands();

    private readonly InstructionVariantModel _model;

    internal InstructionVariant(string mnemonic, bool hasOperands, InstructionVariantModel model)
    {
        _model = model;
        
        this.Mnemonic = mnemonic;
        this.VariantFlags = (InstructionVariantFlag) model.Flags;
        this.VariantPriority = model.Priority;
        this.HasOperands = hasOperands;
        
        if (!hasOperands)
        {
            _operandDescriptors = ImmutableList<OperandDescriptor>.Empty;
        }
    }

    private ImmutableList<OperandDescriptor> ParseOperands()
    {
    }
    

    public bool Equals(InstructionVariant? other)
    {
        if (ReferenceEquals(null, other))
            return false;
        if (ReferenceEquals(this, other))
            return true;

        return this.Mnemonic == other.Mnemonic &&
               this.VariantFlags == other.VariantFlags &&
               _model.DefinitionLine.Equals(other._model.DefinitionLine, StringComparison.Ordinal);
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

        return this.Equals((InstructionVariant) obj);
    }

    public override int GetHashCode()
    {
        return HashCode.Combine(this.Mnemonic, this.VariantFlags, _model.DefinitionLine);
    }
}