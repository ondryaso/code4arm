// SymbolVariable.cs
// Author: Ondřej Ondryáš

using System.Collections.Immutable;
using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class SymbolVariable : IVariable
{
    private readonly uint _address;

    public SymbolVariable(string name, uint address, DebuggerVariableType type)
    {
        _address = address;
        Name = name;
        Type = "symbol value (address)";
        Reference = ReferenceUtils.MakeReference(ContainerType.SymbolAddress, address);
        CanSet = false;
        IsViewOfParent = false;
        Children = ImmutableDictionary<string, IVariable>.Empty.Add($"[{name}]",
            new MemoryVariable($"[{name}]", type, address));
        Parent = null;
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

    public string Get(VariableContext context) => FormattingUtils.FormatAddress(_address);

    public void Set(string value, VariableContext context)
    {
        throw new VariableNotSettableException();
    }
}
