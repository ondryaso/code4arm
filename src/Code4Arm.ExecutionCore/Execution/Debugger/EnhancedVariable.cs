// EnhancedVariable.cs
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

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class EnhancedVariable<TContainedVariable> : IVariable
    where TContainedVariable : IVariable
{
    private readonly TContainedVariable _containedVariable;

    public TContainedVariable ContainedVariable => _containedVariable;

    public EnhancedVariable(TContainedVariable containedVariable, long reference,
        Func<EnhancedVariable<TContainedVariable>, IEnumerable<IVariable>> childrenProducer)
    {
        _containedVariable = containedVariable;

        var children =
            new Dictionary<string, IVariable>(_containedVariable.Children ??
                Enumerable.Empty<KeyValuePair<string, IVariable>>());

        var produced = childrenProducer(this);
        foreach (var child in produced)
        {
            children.Add(child.Name, child);
        }

        Children = children;
        Reference = reference;
    }

    public EnhancedVariable(TContainedVariable containedVariable, long reference,
        Func<EnhancedVariable<TContainedVariable>, IVariable> childProducer)
    {
        _containedVariable = containedVariable;

        var children =
            new Dictionary<string, IVariable>(_containedVariable.Children ??
                Enumerable.Empty<KeyValuePair<string, IVariable>>());

        var produced = childProducer(this);
        children.Add(produced.Name, produced);

        Children = children;
        Reference = reference;
    }

    public EnhancedVariable(TContainedVariable containedVariable, long reference)
    {
        _containedVariable = containedVariable;
        Children = containedVariable.Children;
        Reference = reference;
    }

    public long Reference { get; }
    public IReadOnlyDictionary<string, IVariable>? Children { get; }

    public string Name => _containedVariable.Name;

    public string? Type => _containedVariable.Type;

    public bool CanSet => _containedVariable.CanSet;

    public bool IsViewOfParent => _containedVariable.IsViewOfParent;

    public IVariable? Parent => _containedVariable.Parent;

    public void Evaluate(VariableContext context)
        => _containedVariable.Evaluate(context);

    public string Get(VariableContext context)
        => _containedVariable.Get(context);

    public void Set(string value, VariableContext context)
        => _containedVariable.Set(value, context);
}

public class EnhancedVariable<TBackingValue, TContainedVariable> : ISettableBackedVariable<TBackingValue>
    where TContainedVariable : ISettableBackedVariable<TBackingValue>
{
    private readonly TContainedVariable _containedVariable;

    public TContainedVariable ContainedVariable => _containedVariable;

    public EnhancedVariable(TContainedVariable containedVariable, long reference,
        Func<EnhancedVariable<TBackingValue, TContainedVariable>, IEnumerable<IVariable>> childrenProducer)
    {
        _containedVariable = containedVariable;

        var children =
            new Dictionary<string, IVariable>(_containedVariable.Children ??
                Enumerable.Empty<KeyValuePair<string, IVariable>>());

        var produced = childrenProducer(this);
        foreach (var child in produced)
        {
            children.Add(child.Name, child);
        }

        Children = children;
        Reference = reference;
    }

    public EnhancedVariable(TContainedVariable containedVariable, long reference,
        Func<EnhancedVariable<TBackingValue, TContainedVariable>, IVariable> childProducer)
    {
        _containedVariable = containedVariable;

        var children =
            new Dictionary<string, IVariable>(_containedVariable.Children ??
                Enumerable.Empty<KeyValuePair<string, IVariable>>());

        var produced = childProducer(this);
        children.Add(produced.Name, produced);

        Children = children;
        Reference = reference;
    }

    public EnhancedVariable(TContainedVariable containedVariable, long reference)
    {
        _containedVariable = containedVariable;
        Children = containedVariable.Children;
        Reference = reference;
    }

    public long Reference { get; }
    public IReadOnlyDictionary<string, IVariable>? Children { get; }

    public string Name => _containedVariable.Name;

    public string? Type => _containedVariable.Type;

    public bool CanSet => _containedVariable.CanSet;

    public bool IsViewOfParent => _containedVariable.IsViewOfParent;

    public IVariable? Parent => _containedVariable.Parent;

    public void Evaluate(VariableContext context)
        => _containedVariable.Evaluate(context);

    public string Get(VariableContext context)
        => _containedVariable.Get(context);

    public void Set(string value, VariableContext context)
        => _containedVariable.Set(value, context);

    public TBackingValue GetBackingValue(VariableContext context)
        => _containedVariable.GetBackingValue(context);

    public void Set(TBackingValue value, VariableContext context)
        => _containedVariable.Set(value, context);
}

public class EnhancedAddressBackedVariable<TBackingValue, TContainedVariable>
    : EnhancedVariable<TBackingValue, TContainedVariable>, IAddressBackedVariable
    where TContainedVariable : ISettableBackedVariable<TBackingValue>, IAddressBackedVariable
{
    private readonly IAddressBackedVariable _addressBackedParent;

    public EnhancedAddressBackedVariable(TContainedVariable parent, long reference,
        Func<ISettableBackedVariable<TBackingValue>, IEnumerable<IVariable>> childrenProducer) : base(parent, reference,
        childrenProducer)
    {
        _addressBackedParent = parent;
    }

    public EnhancedAddressBackedVariable(TContainedVariable parent, long reference,
        Func<ISettableBackedVariable<TBackingValue>, IVariable> childProducer) : base(parent, reference, childProducer)
    {
        _addressBackedParent = parent;
    }

    public uint GetAddress() => _addressBackedParent.GetAddress();
}
