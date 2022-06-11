// StackVariable.cs
// Author: Ondřej Ondryáš

using System.Diagnostics.CodeAnalysis;
using Code4Arm.Unicorn;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Abstractions.Extensions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class StackVariable : UIntBackedVariable, IAddressBackedVariable
{
    private readonly uint _address;
    private readonly bool _showFloatIeeeSubvariables;
    private int _index;
    private string _name;

    public StackVariable(uint address, int index, DebuggerVariableType[] allowedSubtypes,
        bool showFloatIeeeSubvariables)
    {
        _address = address;
        _showFloatIeeeSubvariables = showFloatIeeeSubvariables;
        this.SetIndex(index);
        Type = null;

        Reference = ReferenceUtils.MakeReference(ContainerType.StackSubtypes, address);

        if (allowedSubtypes is { Length: not 0 })
        {
            this.MakeChildren(allowedSubtypes);
        }
    }

    [MemberNotNull(nameof(_name))]
    public bool SetIndex(int index)
    {
        var newIndex = index / 4;

        if (newIndex == _index && _name != null)
            return false;
        
        _index = newIndex;
        _name = $"SP+0x{index:x}";

        return true;
    }

    public override string Name => _name;
    public override string? Type { get; }
    public override long Reference { get; }
    public override bool IsViewOfParent => false;

    public override string Get(VariableContext context) => $"[{_index}]@{FormattingUtils.FormatAddress(_address)}";
    public uint GetAddress() => _address;

    public override bool NeedsExplicitEvaluationAfterStep => false;
    public override bool CanPersist => false;
    private UnicornHookRegistration _traceRegistration;

    public override void InitTrace(ExecutionEngine engine, ITraceObserver observer, long traceId)
    {
        base.InitTrace(engine, observer, traceId);

        try
        {
            var value = engine.Engine.MemReadSafe<uint>(_address);
            this.SetTrace(value, false);
        }
        catch (UnicornException)
        {
            // Intentionally left blank: if the read fails, it doesn't really matter
        }

        if (_traceRegistration == default)
            _traceRegistration = engine.Engine.AddMemoryHook((_, _, _, _, value) => { this.SetTrace((uint)value); },
                MemoryHookType.Write, _address, _address + 3);
    }

    public override void TraceStep(ExecutionEngine engine)
    {
    }

    public override void StopTrace(ExecutionEngine engine, ITraceObserver observer)
    {
        base.StopTrace(engine, observer);

        if (!HasObservers)
        {
            _traceRegistration.RemoveHook();
            _traceRegistration = default;
        }
    }

    public override IVariable? Parent => null;

    public override void SetUInt(uint value, VariableContext context)
    {
        context.Engine.Engine.MemWriteSafe(_address, value);
        CurrentValue = value;
    }

    public override void Evaluate(VariableContext context)
    {
        CurrentValue = context.Engine.Engine.MemReadSafe<uint>(_address);
    }

    private void MakeChildren(IEnumerable<DebuggerVariableType> allowedSubtypes)
    {
        foreach (var type in allowedSubtypes.Distinct())
        {
            var variable = new UIntBackedSubtypeVariable<StackVariable>(this, type,
                ReferenceUtils.MakeReference(ContainerType.StackSubtypesValues, _address, type),
                _showFloatIeeeSubvariables);

            ChildrenInternal.Add(variable.Name, variable);
        }
    }
}
