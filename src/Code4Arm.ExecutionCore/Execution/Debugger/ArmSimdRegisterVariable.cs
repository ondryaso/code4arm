// ArmSimdRegisterVariable.cs
// Author: Ondřej Ondryáš

using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class ArmQSimdRegisterVariable : IVariable, ITraceable<ulong[]>
{
    private readonly int _unicornRegId;
    internal readonly ulong[] Values = new ulong[2];

    public ArmQSimdRegisterVariable(int index)
    {
        _unicornRegId = Arm.Register.GetQRegister(index);

        Name = $"Q{index}";
        Reference = ReferenceUtils.MakeReference(ContainerType.SimdRegisterSubtypes, _unicornRegId, 0, 2);

        var a = new ArmDSimdRegisterVariable(index * 2, this, 0);
        var b = new ArmDSimdRegisterVariable((index * 2) + 1, this, 1);
        Children = new Dictionary<string, IVariable>() { { a.Name, a }, { b.Name, b } };
    }

    public string Name { get; }
    public long Reference { get; }
    public IReadOnlyDictionary<string, IVariable>? Children { get; }
    public IVariable? Parent => null;
    public string Type => "128 b";
    public bool CanSet => true;
    public bool IsViewOfParent => false;

    public void Evaluate(VariableContext context)
    {
        var valuesSpan = MemoryMarshal.Cast<ulong, byte>(Values);
        context.Engine.Engine.RegRead(_unicornRegId, valuesSpan);
    }

    public string Get(VariableContext context)
    {
        return Format(Values);
    }

    private static string Format(ReadOnlySpan<ulong> values)
    {
        return values[1] == 0
            ? $"0x{values[0]:x}"
            : $"0x{values[1]:x}{values[0]:x16}";
    }

    public void Set(string value, VariableContext context)
    {
        ReadOnlySpan<char> span;
        var numberStyle = NumberStyles.Number;

        if (value.StartsWith("0x"))
        {
            span = value.AsSpan()[2..];
            numberStyle = NumberStyles.HexNumber;
        }
        else
        {
            span = value.AsSpan();
        }

        if (!BigInteger.TryParse(span, numberStyle, context.CultureInfo, out var i))
            throw new InvalidVariableFormatException(
                "Invalid format. Expected integer (decimal or hex, prefixed with 0x).");

        var valuesSpan = MemoryMarshal.Cast<ulong, byte>(Values);
        valuesSpan.Clear();
        i.TryWriteBytes(valuesSpan, out _);

        context.Engine.Engine.RegWrite(_unicornRegId, valuesSpan);
    }

    public bool NeedsExplicitEvaluationAfterStep => true;
    public bool CanPersist => true;

    private readonly List<RegisteredTraceObserver> _traceObservers = new();
    private readonly ulong[] _traceValues = new ulong[2];

    public void InitTrace(ExecutionEngine engine, ITraceObserver observer, long traceId)
    {
        if (_traceObservers.Count == 0)
            engine.Engine.RegRead(_unicornRegId, MemoryMarshal.Cast<ulong, byte>(_traceValues));

        _traceObservers.Add(new RegisteredTraceObserver(observer, traceId));
    }

    public void InitTrace(ExecutionEngine engine, ITraceObserver<ulong[]> observer, long traceId)
    {
        this.InitTrace(engine, (ITraceObserver)observer, traceId);
    }

    public void TraceStep(ExecutionEngine engine)
    {
        Span<byte> currentValues = stackalloc byte[16];
        engine.Engine.RegRead(_unicornRegId, currentValues);
        var currentValuesUl = MemoryMarshal.Cast<byte, ulong>(currentValues);

        if (currentValuesUl.SequenceEqual(_traceValues))
            return;

        if (_traceObservers.Count != 0)
        {
            foreach (var traceObserver in _traceObservers)
            {
                if (traceObserver.Observer is IFormattedTraceObserver formattedObserver)
                    formattedObserver.TraceTriggered(traceObserver.TraceId, Format(_traceValues),
                        Format(currentValuesUl));
                else if (traceObserver.Observer is ITraceObserver<ulong[]> ulongObserver)
                    ulongObserver.TraceTriggered(traceObserver.TraceId, _traceValues,
                        currentValuesUl.ToArray());
                else
                    traceObserver.Observer.TraceTriggered(traceObserver.TraceId);
            }
        }

        currentValuesUl.CopyTo(_traceValues);
    }

    public void StopTrace(ExecutionEngine engine, ITraceObserver observer)
    {
        _traceObservers.Remove(_traceObservers.Find(t => t.Observer == observer));
    }
}

public class ArmDSimdRegisterVariable : IVariable, ITraceable<ulong>
{
    private readonly int _unicornRegId;
    private readonly ArmQSimdRegisterVariable? _parent;
    private readonly int _parentOffset;
    private ulong _value;

    public ArmDSimdRegisterVariable(int index)
    {
        _unicornRegId = Arm.Register.GetDRegister(index);

        Name = $"D{index}";

        if (index < 16)
        {
            Reference = ReferenceUtils.MakeReference(ContainerType.SimdRegisterSubtypes, _unicornRegId, 0, 1);

            var a = new ArmSSimdRegisterVariable(index * 2, this, 0);
            var b = new ArmSSimdRegisterVariable((index * 2) + 1, this, 1);
            Children = new Dictionary<string, IVariable>() { { a.Name, a }, { b.Name, b } };
        }
        else
        {
            Reference = 0;
            Children = null;
        }

        _parent = null;
        _parentOffset = 0;
    }

    internal ArmDSimdRegisterVariable(int index, ArmQSimdRegisterVariable parent, int parentOffset)
        : this(index)
    {
        _parent = parent;
        _parentOffset = parentOffset;
    }

    public string Name { get; }
    public long Reference { get; }
    public IReadOnlyDictionary<string, IVariable>? Children { get; }
    public IVariable? Parent => _parent;
    public string Type => "64 b";
    public bool CanSet => true;
    public bool IsViewOfParent => _parent != null;

    public void Evaluate(VariableContext context)
    {
        if (_parent != null)
        {
            _parent.Evaluate(context);

            return;
        }

        _value = context.Engine.Engine.RegRead<ulong>(_unicornRegId);
    }

    public string Get(VariableContext context)
    {
        return Format(Value, context);
    }

    private static string Format(ulong value, VariableContext context)
    {
        if (context.Options.ShowSimdRegistersAsFp)
        {
            var d = Unsafe.As<ulong, double>(ref value);

            return d.ToString(context.CultureInfo);
        }

        return $"0x{value:x}";
    }

    internal ulong Value
    {
        get => _parent != null ? _parent.Values[_parentOffset] : _value;
        set
        {
            if (_parent != null)
                _parent.Values[_parentOffset] = value;
            else
                _value = value;
        }
    }

    public void Set(string value, VariableContext context)
    {
        var parsed = FormattingUtils.ParseNumber64U(value, context.CultureInfo);
        Value = parsed;

        context.Engine.Engine.RegWrite(_unicornRegId, parsed);
    }

    public bool NeedsExplicitEvaluationAfterStep => true;
    public bool CanPersist => true;

    private readonly List<RegisteredTraceObserver> _traceObservers = new();
    private ulong _traceValue;

    public void InitTrace(ExecutionEngine engine, ITraceObserver observer, long traceId)
    {
        if (_traceObservers.Count == 0)
            engine.Engine.RegRead(_unicornRegId, ref _traceValue);

        _traceObservers.Add(new RegisteredTraceObserver(observer, traceId));
    }

    public void InitTrace(ExecutionEngine engine, ITraceObserver<ulong> observer, long traceId)
    {
        this.InitTrace(engine, (ITraceObserver)observer, traceId);
    }

    public void TraceStep(ExecutionEngine engine)
    {
        ulong currentValue = 0;
        engine.Engine.RegRead(_unicornRegId, ref currentValue);

        if (currentValue == _traceValue)
            return;

        if (_traceObservers.Count != 0)
        {
            foreach (var traceObserver in _traceObservers)
            {
                var context = traceObserver.Observer.GetTraceTriggerContext();
                if (traceObserver.Observer is IFormattedTraceObserver formattedObserver)
                    formattedObserver.TraceTriggered(traceObserver.TraceId, Format(_traceValue, context),
                        Format(currentValue, context));
                else if (traceObserver.Observer is ITraceObserver<ulong> ulongObserver)
                    ulongObserver.TraceTriggered(traceObserver.TraceId, _traceValue, currentValue);
                else
                    traceObserver.Observer.TraceTriggered(traceObserver.TraceId);
            }
        }

        _traceValue = currentValue;
    }

    public void StopTrace(ExecutionEngine engine, ITraceObserver observer)
    {
        _traceObservers.Remove(_traceObservers.Find(t => t.Observer == observer));
    }
}

public class ArmSSimdRegisterVariable : UIntBackedVariable
{
    private readonly int _unicornRegId;
    private readonly ArmDSimdRegisterVariable? _parent;
    private readonly ulong _mask;
    private readonly int _shift;

    public ArmSSimdRegisterVariable(int index)
    {
        _unicornRegId = Arm.Register.GetSRegister(index);

        Name = $"S{index}";
        Reference = ReferenceUtils.MakeReference(ContainerType.SimdRegisterSubtypes, _unicornRegId, 0, 0);

        // TODO: make this configurable
        this.MakeChildren(new[] { DebuggerVariableType.Float, DebuggerVariableType.IntS, DebuggerVariableType.IntU });
    }

    internal ArmSSimdRegisterVariable(int index, ArmDSimdRegisterVariable parent, int parentOffset)
        : this(index)
    {
        _parent = parent;
        _shift = parentOffset * 32;
        _mask = 0xFFFFFFFFul << _shift;
    }

    public override string Name { get; }
    public override string Type => "32 b";
    public override long Reference { get; }
    public override bool IsViewOfParent => _parent != null;

    public override uint GetUInt()
    {
        if (_parent != null)
            CurrentValue = unchecked((uint)((_parent.Value & _mask) >> _shift));

        return CurrentValue;
    }

    public override IVariable? Parent => _parent;
    internal override bool ShowFloatIeeeSubvariables => true;

    public override void SetUInt(uint value, VariableContext context)
    {
        if (_parent != null)
            _parent.Value = (_parent.Value & ~_mask) | (((ulong)value) << _shift);

        CurrentValue = value;
        context.Engine.Engine.RegWrite(_unicornRegId, value);
    }

    public override void Evaluate(VariableContext context)
    {
        if (_parent != null)
        {
            _parent.Evaluate(context);
            CurrentValue = unchecked((uint)((_parent.Value & _mask) >> _shift));

            return;
        }

        CurrentValue = context.Engine.Engine.RegRead<uint>(_unicornRegId);
    }

    public override string Get(VariableContext context)
    {
        var value = this.GetUInt();

        if (context.Options.ShowSimdRegistersAsFp)
        {
            var d = Unsafe.As<uint, float>(ref value);

            return d.ToString(context.CultureInfo);
        }

        return $"0x{value:x}";
    }

    public override bool NeedsExplicitEvaluationAfterStep => true;
    public override bool CanPersist => true;

    public override void TraceStep(ExecutionEngine engine)
    {
        var value = engine.Engine.RegRead<uint>(_unicornRegId);
        this.SetTrace(value);
    }

    private void MakeChildren(IEnumerable<DebuggerVariableType> allowedSubtypes)
    {
        foreach (var type in allowedSubtypes)
        {
            var variable = new UIntBackedSubtypeVariable(this, type,
                ReferenceUtils.MakeReference(ContainerType.SimdRegisterSubtypesValues, _unicornRegId, type));

            ChildrenInternal.Add(variable.Name, variable);
        }
    }
}
