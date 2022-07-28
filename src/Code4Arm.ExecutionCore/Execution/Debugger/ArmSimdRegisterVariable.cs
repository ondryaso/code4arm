// ArmSimdRegisterVariable.cs
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

using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class ArmQSimdRegisterVariable : IVariable, ITraceable<ulong[]>
{
    private readonly int _unicornRegId;
    private readonly Dictionary<string, IVariable>? _children;
    internal readonly ulong[] Values = new ulong[2];

    public ArmQSimdRegisterVariable(int index, ArmSimdRegisterVariableOptions options)
    {
        _unicornRegId = Arm.Register.GetQRegister(index);

        Name = $"Q{index}";

        if (options.ShowS || options.ShowD || options.QSubtypes is { Length: not 0 })
        {
            Reference = ReferenceUtils.MakeReference(ContainerType.SimdRegisterSubtypes, _unicornRegId, 0, 2);
            _children = new Dictionary<string, IVariable>();

            var showS = options.ShowS && !options.ShowD && index < 8;
            if (showS)
                this.MakeSChildren(index, options);

            if (options.ShowD)
                this.MakeDChildren(index, options);

            if (options.QSubtypes is { Length: not 0 })
                this.MakeChildren(options.QSubtypes, options.ShowD, showS, index, options);
        }
        else
        {
            Reference = 0;
            _children = null;
        }
    }

    public string Name { get; }
    public long Reference { get; }
    public IReadOnlyDictionary<string, IVariable>? Children => _children;
    public IVariable? Parent => null;
    public string Type => "128-bit SIMD/FP register";
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

    private void MakeChildren(IEnumerable<DebuggerVariableType> allowedSubtypes, bool ignoreDoubles, bool ignoreFloats,
        int thisIndex, ArmSimdRegisterVariableOptions options)
    {
        foreach (var type in allowedSubtypes.Distinct())
        {
            if (ignoreDoubles && type == DebuggerVariableType.Double)
                continue;
            if (ignoreFloats && type == DebuggerVariableType.Float)
                continue;

            // TODO: Subvariables for the 128-bit Q-registers

            if (type is DebuggerVariableType.Double or DebuggerVariableType.LongU && !ignoreDoubles)
            {
                // Temporary solution
                this.MakeDChildren(thisIndex,
                    options with { PreferFloatRendering = type == DebuggerVariableType.Double });
            }

            if (type is DebuggerVariableType.Float or DebuggerVariableType.IntU && thisIndex < 8 && !ignoreFloats)
            {
                // Temporary solution
                this.MakeSChildren(thisIndex,
                    options with { PreferFloatRendering = type == DebuggerVariableType.Float });
            }
        }
    }

    private void MakeDChildren(int thisIndex, ArmSimdRegisterVariableOptions options)
    {
        var a = new ArmDSimdRegisterVariable(thisIndex * 2, this, 0, options);
        var b = new ArmDSimdRegisterVariable((thisIndex * 2) + 1, this, 1, options);

        _children!.Add(a.Name, a);
        _children!.Add(b.Name, b);
    }

    private void MakeSChildren(int thisIndex, ArmSimdRegisterVariableOptions options)
    {
        var sBaseIndex = thisIndex * 4;
        for (var i = 0; i < 4; i++)
        {
            // TODO: add Q-parented S-variables
            var child = new ArmSSimdRegisterVariable(sBaseIndex + i, options);
            _children!.Add(child.Name, child);
        }
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

public class ArmDSimdRegisterVariable : IVariable, ITraceable<ulong>, ISettableBackedVariable<double>,
                                        ISettableBackedVariable<ulong>
{
    private readonly bool _showIeee;
    private readonly bool _showAsFloat;
    private readonly int _unicornRegId;
    private readonly ArmQSimdRegisterVariable? _parent;
    private readonly int _parentOffset;
    private ulong _value;
    private readonly Dictionary<string, IVariable>? _children;

    public ArmDSimdRegisterVariable(int index, ArmSimdRegisterVariableOptions options)
    {
        _unicornRegId = Arm.Register.GetDRegister(index);

        Name = $"D{index}";
        Type = options.PreferFloatRendering
            ? "64 bit SIMD/FP register (interpreted as a double-precision floating-point number)"
            : "64 bit SIMD/FP register";

        var showS = options.ShowS && index < 16;
        _showIeee = options.DIeeeSubvariables;
        _showAsFloat = options.PreferFloatRendering;

        if (showS || options.DIeeeSubvariables || options.DSubtypes is { Length: not 0 })
        {
            Reference = ReferenceUtils.MakeReference(ContainerType.SimdRegisterSubtypes, _unicornRegId, 0, 1);
            _children = new Dictionary<string, IVariable>();

            if (showS)
                this.MakeSChildren(index, options);

            if (options.DSubtypes is { Length: not 0 })
                this.MakeChildren(options.DSubtypes, showS);

            if (options.DIeeeSubvariables &&
                (options.DSubtypes is not { Length: not 0 } ||
                    !options.DSubtypes.Contains(DebuggerVariableType.Double)))
                this.MakeIeeeChildren();
        }
        else
        {
            Reference = 0;
            _children = null;
        }

        _parent = null;
        _parentOffset = 0;
    }

    internal ArmDSimdRegisterVariable(int index, ArmQSimdRegisterVariable parent, int parentOffset,
        ArmSimdRegisterVariableOptions options)
        : this(index, options)
    {
        _parent = parent;
        _parentOffset = parentOffset;
    }

    double IBackedVariable<double>.GetBackingValue(VariableContext context)
    {
        var valU = this.GetBackingValue(context);

        return Unsafe.As<ulong, double>(ref valU);
    }

    public ulong GetBackingValue(VariableContext context) => Value;

    public string Name { get; }
    public long Reference { get; }
    public IReadOnlyDictionary<string, IVariable>? Children => _children;
    public IVariable? Parent => _parent;
    public string Type { get; }
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
        return this.Format(Value, context);
    }

    private string Format(ulong value, VariableContext context)
    {
        if (_showAsFloat || context.NumberFormat == VariableNumberFormat.Float)
        {
            var d = Unsafe.As<ulong, double>(ref value);

            return d.ToString(context.CultureInfo);
        }
        else
        {
            return FormattingUtils.FormatAnyVariable(value, context, 64, (unchecked((long)value)) < 0);
        }
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
        this.Set(parsed, context);
    }

    public void Set(double value, VariableContext context)
    {
        var valU = Unsafe.As<double, ulong>(ref value);
        this.Set(valU, context);
    }

    public void Set(ulong value, VariableContext context)
    {
        Value = value;

        context.Engine.Engine.RegWrite(_unicornRegId, value);
    }

    private void MakeChildren(IEnumerable<DebuggerVariableType> allowedSubtypes, bool ignoreFloats)
    {
        foreach (var type in allowedSubtypes.Distinct())
        {
            if (ignoreFloats && type == DebuggerVariableType.Float)
                continue;

            var variable = new ULongBackedSubtypeVariable<ArmDSimdRegisterVariable>(this, type,
                ReferenceUtils.MakeReference(ContainerType.SimdRegisterSubtypesValues, _unicornRegId, type), _showIeee);

            _children!.Add(variable.Name, variable);
        }
    }

    private void MakeIeeeChildren()
    {
        var sign = new DoublePrecisionIeeeSegmentVariable(this, IeeeSegment.Sign);
        var exp = new DoublePrecisionIeeeSegmentVariable(this, IeeeSegment.Exponent);
        var mant = new DoublePrecisionIeeeSegmentVariable(this, IeeeSegment.Mantissa);

        _children!.Add(sign.Name, sign);
        _children.Add(exp.Name, exp);
        _children.Add(mant.Name, mant);
    }

    private void MakeSChildren(int thisIndex, ArmSimdRegisterVariableOptions options)
    {
        var a = new ArmSSimdRegisterVariable(thisIndex * 2, this, 0, options);
        var b = new ArmSSimdRegisterVariable((thisIndex * 2) + 1, this, 1, options);

        _children!.Add(a.Name, a);
        _children!.Add(b.Name, b);
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
                    formattedObserver.TraceTriggered(traceObserver.TraceId, this.Format(_traceValue, context),
                        this.Format(currentValue, context));
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
    private readonly bool _showAsFloat;
    private readonly bool _showIeee;
    private readonly int _unicornRegId;
    private readonly ArmDSimdRegisterVariable? _dParent;
    private readonly ulong _mask;
    private readonly int _shift;

    public ArmSSimdRegisterVariable(int index, ArmSimdRegisterVariableOptions options)
    {
        _showAsFloat = options.PreferFloatRendering;
        _showIeee = options.SIeeeSubvariables;
        _unicornRegId = Arm.Register.GetSRegister(index);

        Name = $"S{index}";
        Type = options.PreferFloatRendering
            ? "32 bit SIMD/FP register (interpreted as a single-precision floating-point number)"
            : "32 bit SIMD/FP register";

        if (options.SSubtypes is { Length: not 0 } || options.SIeeeSubvariables)
        {
            Reference = ReferenceUtils.MakeReference(ContainerType.SimdRegisterSubtypes, _unicornRegId, 0, 0);

            if (options.SSubtypes is { Length: not 0 })
            {
                this.MakeChildren(options.SSubtypes);
            }

            if (options.SIeeeSubvariables &&
                (options.SSubtypes is not { Length: not 0 } || !options.SSubtypes.Contains(DebuggerVariableType.Float)))
            {
                this.MakeIeeeChildren();
            }
        }
        else
        {
            Reference = 0;
        }
    }

    internal ArmSSimdRegisterVariable(int index, ArmDSimdRegisterVariable dParent, int parentOffset,
        ArmSimdRegisterVariableOptions options)
        : this(index, options)
    {
        _dParent = dParent;
        _shift = parentOffset * 32;
        _mask = 0xFFFFFFFFul << _shift;
    }

    public override string Name { get; }
    public override string Type { get; }
    public override long Reference { get; }
    public override bool IsViewOfParent => _dParent != null;

    public override uint GetUInt()
    {
        if (_dParent != null)
            CurrentValue = unchecked((uint)((_dParent.Value & _mask) >> _shift));

        return CurrentValue;
    }

    public override IVariable? Parent => _dParent;

    public override void SetUInt(uint value, VariableContext context)
    {
        if (_dParent != null)
            _dParent.Value = (_dParent.Value & ~_mask) | (((ulong)value) << _shift);

        CurrentValue = value;
        context.Engine.Engine.RegWrite(_unicornRegId, value);
    }

    public override void Evaluate(VariableContext context)
    {
        if (_dParent != null)
        {
            _dParent.Evaluate(context);
            CurrentValue = unchecked((uint)((_dParent.Value & _mask) >> _shift));

            return;
        }

        CurrentValue = context.Engine.Engine.RegRead<uint>(_unicornRegId);
    }

    protected override string Format(uint value, VariableContext context)
    {
        if (_showAsFloat || context.NumberFormat == VariableNumberFormat.Float)
        {
            var d = Unsafe.As<uint, float>(ref value);

            return d.ToString(context.CultureInfo);
        }
        else
        {
            return FormattingUtils.FormatVariable(value, context);
        }
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
        foreach (var type in allowedSubtypes.Distinct())
        {
            var variable = new UIntBackedSubtypeVariable<ArmSSimdRegisterVariable>(this, type,
                ReferenceUtils.MakeReference(ContainerType.SimdRegisterSubtypesValues, _unicornRegId, type), _showIeee);

            ChildrenInternal.Add(variable.Name, variable);
        }
    }

    private void MakeIeeeChildren()
    {
        var sign = new SinglePrecisionIeeeSegmentVariable(this, IeeeSegment.Sign);
        var exp = new SinglePrecisionIeeeSegmentVariable(this, IeeeSegment.Exponent);
        var mant = new SinglePrecisionIeeeSegmentVariable(this, IeeeSegment.Mantissa);

        ChildrenInternal.Add(sign.Name, sign);
        ChildrenInternal.Add(exp.Name, exp);
        ChildrenInternal.Add(mant.Name, mant);
    }
}
