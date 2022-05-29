// RegisterVariable.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class RegisterVariable : UnstructuredRegisterVariable
{
    private readonly bool _showIeeeFloatSubvariables;

    public RegisterVariable(int unicornRegisterId, string name, DebuggerVariableType[] allowedSubtypes,
        bool showIeeeFloatSubvariables)
        : base(unicornRegisterId, name, null)
    {
        _showIeeeFloatSubvariables = showIeeeFloatSubvariables;
        Reference = ReferenceUtils.MakeReference(ContainerType.RegisterSubtypes, unicornRegisterId);

        if (allowedSubtypes is { Length: not 0 })
        {
            this.MakeChildren(allowedSubtypes);
        }
    }

    public RegisterVariable(long reference, int unicornRegisterId, string name, DebuggerVariableType? targetSubtype,
        bool showIeeeFloatSubvariables)
        : base(unicornRegisterId, name, null)
    {
        _showIeeeFloatSubvariables = showIeeeFloatSubvariables;
        if (targetSubtype.HasValue)
        {
            Reference = reference;
            this.MakeChildren(new[] { targetSubtype.Value });
        }
        else
        {
            Reference = 0;
        }
    }

    public override long Reference { get; }

    private void MakeChildren(IEnumerable<DebuggerVariableType> allowedSubtypes)
    {
        foreach (var type in allowedSubtypes.Distinct())
        {
            var variable = new UIntBackedSubtypeVariable<RegisterVariable>(this, type,
                ReferenceUtils.MakeReference(ContainerType.RegisterSubtypesValues, UnicornRegisterId, type),
                _showIeeeFloatSubvariables);

            ChildrenInternal.Add(variable.Name, variable);
        }
    }
}
