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

public class MemoryVariable : IVariable, ITraceable
{
    private readonly DebuggerVariableType _type;
    private readonly uint _address;
    private readonly int _size;
    private string? _value;

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

    public string Name { get; }
    public string? Type { get; }
    public long Reference { get; }

    public bool CanSet => true;
    public bool IsViewOfParent => false;
    public IReadOnlyDictionary<string, IVariable>? Children { get; }
    public IVariable? Parent => null;

    public void Evaluate(VariableContext context)
    {
        try
        {
            if (_type == DebuggerVariableType.Float)
            {
                var v = context.Engine.Engine.MemReadSafe<float>(_address);
                _value = v.ToString(context.CultureInfo);
            }
            else if (_type == DebuggerVariableType.Double)
            {
                var v = context.Engine.Engine.MemReadSafe<double>(_address);
                _value = v.ToString(context.CultureInfo);
            }
            else
            {
                // TODO: make more effective
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
                (unicorn, _, _, _, _) => { this.UpdateTrace(unicorn); }, MemoryHookType.Write, _address,
                (ulong)(_address + _size - 1));

            this.UpdateTrace(engine.Engine, false);
        }
    }

    private void UpdateTrace(IUnicorn unicorn, bool notify = true)
    {
        ulong newValue = 0;
        var newValueSpan = MemoryMarshal.CreateSpan(ref newValue, 1);
        var newValueBytes = MemoryMarshal.Cast<ulong, byte>(newValueSpan);
        unicorn.MemRead(_address, newValueBytes, (nuint)_size);

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
