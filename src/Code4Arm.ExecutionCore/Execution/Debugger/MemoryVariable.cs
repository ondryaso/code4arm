// MemoryVariable.cs
// Author: Ondřej Ondryáš

using System.Buffers;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.Unicorn;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Abstractions.Extensions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class MemoryVariable : IVariable, ITraceable, ISettableBackedVariable<float>, ISettableBackedVariable<double>,
                              IAddressBackedVariable
{
    private readonly DebuggerVariableType _type;
    private readonly uint _address;
    private readonly int _size;
    private string? _value;
    private float _floatValue;
    private double _doubleValue;

    public MemoryVariable(string name, DebuggerVariableType type, uint address)
    {
        _type = type;
        _address = address;
        Name = name;
        Type = type.GetName();

        _size = type.GetSize();
        Reference = 0; // TODO
        Children = null;
    }

    float IBackedVariable<float>.GetBackingValue(VariableContext context)
    {
        if (_type != DebuggerVariableType.Float)
            throw new InvalidOperationException("This memory variable is not a float variable.");

        return _floatValue;
    }

    double IBackedVariable<double>.GetBackingValue(VariableContext context)
    {
        if (_type != DebuggerVariableType.Double)
            throw new InvalidOperationException("This memory variable is not a double variable.");

        return _doubleValue;
    }

    public void Set(float value, VariableContext context)
    {
        try
        {
            context.Engine.Engine.MemWriteSafe(_address, value);
        }
        catch (UnicornException e) when (e.Error.IsMemoryError())
        {
            throw new InvalidMemoryOperationException(ExceptionMessages.InvalidMemoryWrite, e);
        }
    }

    public void Set(double value, VariableContext context)
    {
        try
        {
            context.Engine.Engine.MemWriteSafe(_address, value);
        }
        catch (UnicornException e) when (e.Error.IsMemoryError())
        {
            throw new InvalidMemoryOperationException(ExceptionMessages.InvalidMemoryWrite, e);
        }
    }

    public string Name { get; }
    public string? Type { get; }
    public long Reference { get; }

    public bool CanSet => true;
    public bool IsViewOfParent => false;
    public IReadOnlyDictionary<string, IVariable>? Children { get; }
    public IVariable? Parent => null;

    public void Evaluate(VariableContext context)
    {
        // All the types are actually covered
#pragma warning disable CS8509
        try
        {
            if (_size == 1)
            {
                var v = context.Engine.Engine.MemReadSafe<byte>(_address);
                _value = _type switch
                {
                    DebuggerVariableType.ByteS => FormattingUtils.FormatSignedVariable(unchecked((sbyte)v), context, 8),
                    DebuggerVariableType.ByteU => FormattingUtils.FormatVariable(v, context, 8),
                    DebuggerVariableType.CharAscii => ((char)v).ToString()
                };
            }
            else if (_size == 2)
            {
                var v = context.Engine.Engine.MemReadSafe<ushort>(_address);
                _value = _type switch
                {
                    DebuggerVariableType.ShortS => FormattingUtils.FormatSignedVariable(unchecked((short)v), context,
                        16),
                    DebuggerVariableType.ShortU => FormattingUtils.FormatVariable(v, context)
                };
            }
            else if (_size == 4)
            {
                var v = context.Engine.Engine.MemReadSafe<uint>(_address);

                if (_type == DebuggerVariableType.Float)
                    _floatValue = Unsafe.As<uint, float>(ref v);

                _value = _type switch
                {
                    DebuggerVariableType.IntS => FormattingUtils.FormatSignedVariable(unchecked((int)v), context),
                    DebuggerVariableType.IntU => FormattingUtils.FormatVariable(v, context),
                    DebuggerVariableType.Float => _floatValue.ToString(context.CultureInfo)
                };
            }
            else if (_size == 8)
            {
                var v = context.Engine.Engine.MemReadSafe<ulong>(_address);

                if (_type == DebuggerVariableType.Double)
                    _doubleValue = Unsafe.As<ulong, double>(ref v);

                _value = _type switch
                {
                    DebuggerVariableType.LongS => FormattingUtils.FormatAnyVariable(unchecked((long)v), context,
                        64, unchecked((long)v) < 0),
                    DebuggerVariableType.LongU => FormattingUtils.FormatAnyVariable(v, context, 64, false),
                    DebuggerVariableType.Double => _doubleValue.ToString(context.CultureInfo)
                };
            }
            else
            {
                // Not gonna get here
                Span<byte> bytes = stackalloc byte[_size];
                context.Engine.Engine.MemRead(_address, bytes);
                var bi = new BigInteger(bytes);
                _value = bi.ToString(context.CultureInfo);
            }
        }
        catch (UnicornException e) when (e.Error.IsMemoryError())
        {
            throw new InvalidMemoryOperationException(ExceptionMessages.InvalidMemoryRead, e);
        }
#pragma warning restore CS8509
    }

    public string Get(VariableContext context) => _value ?? string.Empty;

    public void Set(string value, VariableContext context)
    {
        try
        {
            if (_type == DebuggerVariableType.Float)
            {
                var v = FormattingUtils.ParseNumber32F(value, context.CultureInfo);
                context.Engine.Engine.MemWriteSafe(_address, v);
            }
            else if (_type == DebuggerVariableType.Double)
            {
                var v = FormattingUtils.ParseNumber64F(value, context.CultureInfo);
                context.Engine.Engine.MemWriteSafe(_address, v);
            }
            else if (_size <= 4)
            {
                var v = FormattingUtils.ParseNumber32U(value, context.CultureInfo);
                context.Engine.Engine.MemWriteSafe(_address, v, (nuint)_size);
            }
            else if (_size == 8)
            {
                var v = FormattingUtils.ParseNumber64U(value, context.CultureInfo);
                context.Engine.Engine.MemWriteSafe(_address, v);
            }
        }
        catch (UnicornException e) when (e.Error.IsMemoryError())
        {
            throw new InvalidMemoryOperationException(ExceptionMessages.InvalidMemoryWrite, e);
        }
    }

    public uint GetAddress() => _address;

    public bool NeedsExplicitEvaluationAfterStep => false;
    public bool CanPersist => false;

    private UnicornHookRegistration _traceRegistration;
    private readonly List<RegisteredTraceObserver> _traceObservers = new();
    private ulong _traceValue;

    public void InitTrace(ExecutionEngine engine, ITraceObserver observer, long traceId)
    {
        _traceObservers.Add(new RegisteredTraceObserver(observer, traceId));

        if (_traceRegistration == default)
        {
            _traceRegistration = engine.Engine.AddMemoryHook(
                (unicorn, _, _, _, val) => { this.UpdateTrace(unicorn, unchecked((ulong)val)); }, MemoryHookType.Write, _address,
                (ulong)(_address + _size - 1));

            this.UpdateTrace(engine.Engine, 0, false);
        }
    }

    private void UpdateTrace(IUnicorn unicorn, ulong val, bool notify = true)
    {
        ulong newValue = val & ~ ((~0ul) << (_size << 3));

        if (_traceValue == newValue)
            return;

        if (notify && _traceObservers.Count != 0)
        {
            foreach (var traceObserver in _traceObservers)
            {
                var observer = traceObserver.Observer;
                var context = observer.GetTraceTriggerContext();

                switch (observer)
                {
                    case IFormattedTraceObserver formattedObserver:
                        formattedObserver.TraceTriggered(traceObserver.TraceId, this.Format(_traceValue, context),
                            this.Format(newValue, context));

                        break;
                    default:
                        observer.TraceTriggered(traceObserver.TraceId);

                        break;
                }
            }
        }

        _traceValue = newValue;
    }

    private string Format(ulong value, VariableContext context)
    {
        if (_type == DebuggerVariableType.Float)
        {
            var masked = (uint)(value & 0xFFFFFFFF);
            var v = Unsafe.As<uint, float>(ref masked);

            return v.ToString(context.CultureInfo);
        }
        else if (_type == DebuggerVariableType.Double)
        {
            var v = Unsafe.As<ulong, float>(ref value);

            return v.ToString(context.CultureInfo);
        }
        else
        {
            return value.ToString(context.CultureInfo);
        }
    }

    public void TraceStep(ExecutionEngine engine)
    {
    }

    public void StopTrace(ExecutionEngine engine, ITraceObserver observer)
    {
        _traceObservers.Remove(_traceObservers.Find(t => t.Observer == observer));

        if (_traceObservers.Count == 0)
        {
            _traceRegistration.RemoveHook();
            _traceRegistration = default;
        }
    }
}
