// SymbolVariable.cs
// Author: Ondřej Ondryáš

using System.Collections.Immutable;
using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class SymbolVariable : IVariable
{
    private readonly uint _address;
    private readonly string _typeName;

    public SymbolVariable(string name, uint address, DebuggerVariableType type)
        : this(name, address, false)
    {
        Children = ImmutableDictionary<string, IVariable>.Empty.Add($"[{name}]",
            new MemoryVariable($"[{name}]", type, address));
        
        _typeName = type.GetName();
    }

    public SymbolVariable(string name, uint address, bool isStringSymbol)
    {
        _address = address;
        Name = name;
        Type = "symbol value (address)";
        Reference = ReferenceUtils.MakeReference(ContainerType.SymbolAddress, address);
        CanSet = false;
        IsViewOfParent = false;
        Parent = null;

        Children = isStringSymbol
            ? ImmutableDictionary<string, IVariable>.Empty.Add($"[{name}]",
                new StringVariable($"[{name}]", address))
            : null;

        _typeName = isStringSymbol ? "string" : string.Empty;
    }

    public string Name { get; }
    public string? Type { get; }
    public long Reference { get; }
    public bool CanSet { get; }
    public bool IsViewOfParent { get; }
    public IReadOnlyDictionary<string, IVariable>? Children { get; }
    public IVariable? Parent { get; }

    public void Evaluate(VariableContext context)
    {
    }

    public string Get(VariableContext context) => $"{_typeName} at {FormattingUtils.FormatAddress(_address)}";

    public void Set(string value, VariableContext context)
    {
        throw new VariableNotSettableException();
    }
}
