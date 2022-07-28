// RegisterVariable.cs
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
