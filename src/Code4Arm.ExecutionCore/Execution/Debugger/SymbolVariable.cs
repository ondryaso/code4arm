// SymbolVariable.cs
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
