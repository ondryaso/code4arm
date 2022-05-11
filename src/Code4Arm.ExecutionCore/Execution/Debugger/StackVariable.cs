// StackVariable.cs
// Author: Ondřej Ondryáš

using Code4Arm.Unicorn.Abstractions.Extensions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class StackVariable : UIntBackedVariable
{
    private readonly uint _address;

    public StackVariable(uint address, int index, Subtype[] allowedSubtypes)
    {
        _address = address;
        Name = $"[{index}]";
        Type = null;
        Reference = ReferenceUtils.MakeReference(ContainerType.StackSubtypes, address);
        
        this.MakeChildren(allowedSubtypes);
    }

    public override string Name { get; }
    public override string? Type { get; }
    public override long Reference { get; }

    public override string Get(VariableContext context) => string.Empty;

    public override void SetUInt(uint value, VariableContext context)
    {
        context.Engine.Engine.MemWriteSafe(_address, value);
    }

    public override void Evaluate(VariableContext context)
    {
        CurrentValue = context.Engine.Engine.MemReadSafe<uint>(_address);
    }
    
    private void MakeChildren(Subtype[] allowedSubtypes)
    {
        foreach (var type in allowedSubtypes)
        {
            var variable = new UIntBackedSubtypeVariable(this, type,
                ReferenceUtils.MakeReference(ContainerType.StackSubtypesValues, _address, type));

            ChildrenInternal.Add(variable.Name, variable);
        }
    }
}
