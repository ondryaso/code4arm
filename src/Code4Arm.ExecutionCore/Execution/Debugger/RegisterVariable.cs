﻿// RegisterVariable.cs
// Author: Ondřej Ondryáš

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class RegisterVariable : UnstructuredRegisterVariable
{
    public RegisterVariable(int unicornRegisterId, string name, DebuggerVariableType[] allowedSubtypes,
        bool showIeeeFloatSubvariables)
        : base(unicornRegisterId, name, null, showIeeeFloatSubvariables)
    {
        Reference = ReferenceUtils.MakeReference(ContainerType.RegisterSubtypes, unicornRegisterId);

        this.MakeChildren(allowedSubtypes);
    }

    public RegisterVariable(long reference, int unicornRegisterId, string name, DebuggerVariableType? targetSubtype,
        bool showIeeeFloatSubvariables)
        : base(unicornRegisterId, name, null, showIeeeFloatSubvariables)
    {
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
