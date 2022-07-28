// InstructionVariant.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

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
