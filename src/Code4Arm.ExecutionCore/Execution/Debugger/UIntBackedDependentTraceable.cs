// UIntBackedDependentTraceable.cs
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

/// <summary>
/// Represents a stepped <see cref="ITraceable"/> that delegates to an <see cref="ITraceable"/> parent. 
/// It registers itself as an observer to the parent, listening for <see langword="uint"/>-valued trace events
/// and updating its observer with a set of values calculated from the parent's value using a mask and an offset.
/// It can operate both in stepped and hooked mode, the <see cref="NeedsExplicitEvaluationAfterStep"/> property
/// mirrors the parent.
/// </summary>
public abstract class UIntBackedDependentTraceable : ITraceable, ITraceObserver<uint>
{
    private readonly ITraceable _parent;
    private readonly uint _mask;
    private readonly int _offset;

    public bool NeedsExplicitEvaluationAfterStep => _parent.NeedsExplicitEvaluationAfterStep;
    public bool CanPersist => true;
    private IFormattedTraceObserver? _traceObserver;
    private long _traceId;

    protected UIntBackedDependentTraceable(ITraceable parent, uint mask, int offset)
    {
        _parent = parent;
        _mask = mask;
        _offset = offset;
    }
    
    protected abstract string Format(uint value, VariableContext context);

    public void InitTrace(ExecutionEngine engine, ITraceObserver observer, long traceId)
    {
        if (_traceObserver != null && observer != _traceObserver)
            throw new InvalidOperationException(
                "This traceable doesn't support more than one observer.");

        if (observer is not IFormattedTraceObserver formattedTraceObserver)
            throw new InvalidOperationException(
                "This traceable only supports an IFormattedTraceObserver.");

        _traceObserver = formattedTraceObserver;
        _traceId = traceId;
        _parent.InitTrace(engine, this, 0);
    }

    public void TraceStep(ExecutionEngine engine)
    {
        _parent.TraceStep(engine);
    }

    public void StopTrace(ExecutionEngine engine, ITraceObserver observer)
    {
        if (observer != _traceObserver)
            throw new InvalidOperationException(
                "This dependent traceable doesn't support more than one observer.");

        _traceObserver = null;
        _parent.StopTrace(engine, this);
    }

    public void TraceTriggered(long traceId, uint originalValue, uint newValue)
    {
        originalValue = (originalValue >> _offset) & _mask;
        newValue = (newValue >> _offset) & _mask;

        if (originalValue != newValue && _traceObserver != null)
        {
            var context = _traceObserver.GetTraceTriggerContext();
            _traceObserver?.TraceTriggered(_traceId, this.Format(originalValue, context),
                this.Format(newValue, context));
        }
    }

    public VariableContext GetTraceTriggerContext() => _traceObserver?.GetTraceTriggerContext()
        ?? throw new InvalidOperationException();

    public void TraceTriggered(long traceId)
    {
        throw new InvalidOperationException("This dependent traceable only accepts trace events with uint values.");
    }
}
