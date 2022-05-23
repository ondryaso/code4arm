// EnhancedVariable.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class EnhancedVariable<TBackingValue> : ISettableBackedVariable<TBackingValue>
{
    private readonly ISettableBackedVariable<TBackingValue> _parent;

    public EnhancedVariable(ISettableBackedVariable<TBackingValue> parent, long reference,
        Func<ISettableBackedVariable<TBackingValue>, IEnumerable<IVariable>> childrenProducer)
    {
        _parent = parent;

        var children =
            new Dictionary<string, IVariable>(_parent.Children ?? Enumerable.Empty<KeyValuePair<string, IVariable>>());

        var produced = childrenProducer(this);
        foreach (var child in produced)
        {
            children.Add(child.Name, child);
        }

        Children = children;
        Reference = reference;
    }

    public EnhancedVariable(ISettableBackedVariable<TBackingValue> parent, long reference,
        Func<ISettableBackedVariable<TBackingValue>, IVariable> childProducer)
    {
        _parent = parent;

        var children =
            new Dictionary<string, IVariable>(_parent.Children ?? Enumerable.Empty<KeyValuePair<string, IVariable>>());

        var produced = childProducer(this);
        children.Add(produced.Name, produced);

        Children = children;
        Reference = reference;
    }

    public long Reference { get; }
    public IReadOnlyDictionary<string, IVariable> Children { get; }

    public string Name => _parent.Name;

    public string? Type => _parent.Type;

    public bool CanSet => _parent.CanSet;

    public bool IsViewOfParent => _parent.IsViewOfParent;

    public IVariable? Parent => _parent.Parent;

    public void Evaluate(VariableContext context)
        => _parent.Evaluate(context);

    public string Get(VariableContext context)
        => _parent.Get(context);

    public void Set(string value, VariableContext context)
        => _parent.Set(value, context);

    public TBackingValue GetBackingValue(VariableContext context)
        => _parent.GetBackingValue(context);

    public void Set(TBackingValue value, VariableContext context)
        => _parent.Set(value, context);
}

public class EnhancedAddressBackedVariable<TBackingValue, TParent> : EnhancedVariable<TBackingValue>,
    IAddressBackedVariable where TParent : ISettableBackedVariable<TBackingValue>, IAddressBackedVariable
{
    private readonly IAddressBackedVariable _addressBackedParent;

    public EnhancedAddressBackedVariable(TParent parent, long reference,
        Func<ISettableBackedVariable<TBackingValue>, IEnumerable<IVariable>> childrenProducer) : base(parent, reference,
        childrenProducer)
    {
        _addressBackedParent = parent;
    }

    public EnhancedAddressBackedVariable(TParent parent, long reference,
        Func<ISettableBackedVariable<TBackingValue>, IVariable> childProducer) : base(parent, reference, childProducer)
    {
        _addressBackedParent = parent;
    }

    public uint GetAddress() => _addressBackedParent.GetAddress();
}
