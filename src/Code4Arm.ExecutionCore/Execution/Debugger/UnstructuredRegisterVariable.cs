// UnstructuredRegisterVariable.cs
// Author: Ondřej Ondryáš

using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class UnstructuredRegisterVariable : UIntBackedVariable
{
    protected readonly int UnicornRegisterId;

    public UnstructuredRegisterVariable(int unicornRegisterId, string name, string? type)
    {
        UnicornRegisterId = unicornRegisterId;
        Name = name;
        Type = type;
        Reference = 0;
    }

    public override string Name { get; }
    public override string? Type { get; }
    public override long Reference { get; }
    public override bool IsViewOfParent => false;

    public override IVariable? Parent => null;

    public override void Evaluate(VariableContext context)
    {
        CurrentValue = context.Engine.Engine.RegRead<uint>(UnicornRegisterId);
    }

    public override void SetUInt(uint value, VariableContext context)
    {
        context.Engine.Engine.RegWrite(UnicornRegisterId, value);
        CurrentValue = value;

        if (UnicornRegisterId == Arm.Register.PC)
            context.Engine.CurrentPc = value;
    }
}
