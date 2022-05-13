// RegisterVariable.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class RegisterVariable : UnstructuredRegisterVariable
{
    public RegisterVariable(int unicornRegisterId, string name, DebuggerVariableType[] allowedSubtypes)
        : base(unicornRegisterId, name, null)
    {
        Reference = ReferenceUtils.MakeReference(ContainerType.RegisterSubtypes, unicornRegisterId);

        this.MakeChildren(allowedSubtypes);
    }

    public override long Reference { get; }

    private void MakeChildren(DebuggerVariableType[] allowedSubtypes)
    {
        foreach (var type in allowedSubtypes)
        {
            var variable = new UIntBackedSubtypeVariable(this, type,
                ReferenceUtils.MakeReference(ContainerType.RegisterSubtypesValues, UnicornRegisterId, type));

            ChildrenInternal.Add(variable.Name, variable);
        }
    }
}
