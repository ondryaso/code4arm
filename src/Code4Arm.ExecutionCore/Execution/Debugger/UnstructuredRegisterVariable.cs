// UnstructuredRegisterVariable.cs
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

    public override bool NeedsExplicitEvaluationAfterStep => true;
    public override bool CanPersist => true;

    public override void InitTrace(ExecutionEngine engine, ITraceObserver observer, long traceId)
    {
        base.InitTrace(engine, observer, traceId);
        var currentValue = engine.Engine.RegRead<uint>(UnicornRegisterId);
        this.SetTrace(currentValue, false);
    }

    public override void TraceStep(ExecutionEngine engine)
    {
        var currentValue = engine.Engine.RegRead<uint>(UnicornRegisterId);
        this.SetTrace(currentValue);
    }
}
