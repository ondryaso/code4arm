// UIntVariable.cs
// Author: Ondřej Ondryáš

using System.Runtime.CompilerServices;
using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public abstract class UIntBackedVariable : IVariable, ITraceable
{
    protected readonly Dictionary<string, IVariable> ChildrenInternal = new();
    protected uint CurrentValue;
    internal List<UIntBackedSubtypeAtomicVariable> AtomicVariables = new();

    public abstract string Name { get; }
    public abstract string? Type { get; }
    public abstract long Reference { get; }
    public bool CanSet => true;
    public abstract bool IsViewOfParent { get; }
    public virtual IReadOnlyDictionary<string, IVariable> Children => ChildrenInternal;
    public abstract IVariable? Parent { get; }

    public abstract void SetUInt(uint value, VariableContext context);
    public abstract void Evaluate(VariableContext context);

    public virtual uint GetUInt()
    {
        return CurrentValue;
    }

    public virtual string Get(VariableContext context)
    {
        var value = this.GetUInt();

        return this.Format(value, context);
    }

    public void Set(string value, VariableContext context)
    {
        var number = FormattingUtils.ParseNumber32U(value, context.CultureInfo);
        this.SetUInt(number, context);
    }

    private string Format(uint value, VariableContext context)
        => FormattingUtils.FormatVariable(value, context);

    #region ITraceable

    private readonly List<(ITraceObserver Observer, long TraceId)> _traceObservers = new();
    private uint _traceValue;

    public abstract bool NeedsExplicitEvaluationAfterStep { get; }
    public abstract bool CanPersist { get; }
    protected bool HasObservers => _traceObservers.Count != 0;

    protected void SetTrace(uint newValue, bool notify = true)
    {
        if (_traceValue == newValue)
            return;

        if (notify && _traceObservers.Count != 0)
        {
            foreach (var traceObserver in _traceObservers)
            {
                var context = traceObserver.Observer.GetTraceTriggerContext();
                traceObserver.Observer.TraceTriggered(traceObserver.TraceId, this.Format(_traceValue, context),
                    this.Format(newValue, context));
            }
        }

        foreach (var subtypeVariable in AtomicVariables)
        {
            subtypeVariable.SetTrace(_traceValue, newValue);
        }

        _traceValue = newValue;
    }

    public virtual void InitTrace(ExecutionEngine engine, ITraceObserver observer, long traceId)
    {
        _traceObservers.Add((observer, traceId));
    }

    public abstract void TraceStep(ExecutionEngine engine);

    public virtual void StopTrace(ExecutionEngine engine, ITraceObserver observer)
    {
        _traceObservers.Remove(_traceObservers.Find(t => t.Observer == observer));
    }

    #endregion
}

internal class UIntBackedSubtypeVariable : IVariable
{
    private readonly UIntBackedVariable _parent;
    private readonly DebuggerVariableType _subtype;

    internal UIntBackedSubtypeVariable(UIntBackedVariable parent, DebuggerVariableType subtype, long reference)
    {
        if (subtype is DebuggerVariableType.LongU or DebuggerVariableType.LongS or DebuggerVariableType.Double)
            throw new ArgumentOutOfRangeException(nameof(subtype), subtype, null);

        _parent = parent;
        _subtype = subtype;

        Name = subtype switch
        {
            DebuggerVariableType.ByteU => "unsigned bytes",
            DebuggerVariableType.ByteS => "signed bytes",
            DebuggerVariableType.CharAscii => "chars",
            DebuggerVariableType.ShortU => "unsigned shorts",
            DebuggerVariableType.ShortS => "signed shorts",
            DebuggerVariableType.IntU => "unsigned int",
            DebuggerVariableType.IntS => "signed int",
            DebuggerVariableType.Float => "float",
            _ => throw new ArgumentOutOfRangeException(nameof(subtype), subtype, null)
        };

        Type = null;
        CanSet = subtype is DebuggerVariableType.IntU or DebuggerVariableType.IntS or DebuggerVariableType.Float;
        Reference = reference;
        Children = null;

        if (!CanSet)
        {
            var c = new Dictionary<string, IVariable>();
            var count = (subtype is DebuggerVariableType.ByteU or DebuggerVariableType.ByteS
                or DebuggerVariableType.CharAscii)
                ? 4
                : 2;
            for (var i = 0; i < count; i++)
            {
                var child = new UIntBackedSubtypeAtomicVariable(parent, this, subtype, i);
                c.Add(child.Name, child);
            }

            Children = c;
        }
        else
        {
            Reference = 0;
        }
    }

    public string Name { get; }
    public string? Type { get; }
    public long Reference { get; }
    public bool CanSet { get; }
    public bool IsViewOfParent => true;
    public IReadOnlyDictionary<string, IVariable>? Children { get; }
    public IVariable Parent => _parent;

    public void Evaluate(VariableContext context)
    {
        _parent.Evaluate(context);
    }

    public string Get(VariableContext context)
    {
        if (_subtype is DebuggerVariableType.ByteU or DebuggerVariableType.ByteS or DebuggerVariableType.CharAscii
            or DebuggerVariableType.ShortU or DebuggerVariableType.ShortS)
            return string.Empty;

        var value = _parent.GetUInt();

        return _subtype switch
        {
            DebuggerVariableType.IntU => FormattingUtils.FormatVariable(value, context),
            DebuggerVariableType.IntS => FormattingUtils.FormatVariable(unchecked((int)value), context),
            DebuggerVariableType.Float => Unsafe.As<uint, float>(ref value).ToString(context.CultureInfo),
            _ => string.Empty
        };
    }

    public void Set(string value, VariableContext context)
    {
        var number = _subtype == DebuggerVariableType.Float
            ? FormattingUtils.ParseNumber32F(value, context.CultureInfo)
            : FormattingUtils.ParseNumber32U(value, context.CultureInfo);

        _parent.SetUInt(number, context);
    }
}

internal class UIntBackedSubtypeAtomicVariable : IVariable, ITraceable, ITraceObserver
{
    private readonly UIntBackedVariable _parent;
    private readonly IVariable _treeParent;
    private readonly DebuggerVariableType _subtype;

    private readonly uint _mask;
    private readonly int _offset;

    private readonly int _min, _max;

    internal UIntBackedSubtypeAtomicVariable(UIntBackedVariable parent, IVariable treeParent,
        DebuggerVariableType subtype, int index)
    {
        if (subtype is DebuggerVariableType.IntU or DebuggerVariableType.IntS or DebuggerVariableType.LongU
            or DebuggerVariableType.LongS or DebuggerVariableType.Double)
            throw new ArgumentOutOfRangeException(nameof(subtype), subtype, null);

        _parent = parent;
        _treeParent = treeParent;
        _subtype = subtype;

        _parent.AtomicVariables.Add(this);

        Name = $"[{index}]";
        Type = subtype switch
        {
            DebuggerVariableType.ByteU => "unsigned byte",
            DebuggerVariableType.ByteS => "signed byte",
            DebuggerVariableType.CharAscii => "char",
            DebuggerVariableType.ShortU => "unsigned short",
            DebuggerVariableType.ShortS => "signed short",
            _ => throw new ArgumentOutOfRangeException(nameof(subtype), subtype, null)
        };

        if (subtype is DebuggerVariableType.ByteU or DebuggerVariableType.ByteS or DebuggerVariableType.CharAscii)
        {
            _mask = 0xFF;
            _offset = 8 * index;
        }
        else
        {
            _mask = 0xFFFF;
            _offset = 16 * index;
        }

        if (subtype is DebuggerVariableType.ByteS or DebuggerVariableType.ShortS)
        {
            _min = -((int)_mask / 2) - 1;
            _max = (int)_mask / 2;
        }
        else
        {
            _min = 0;
            _max = (int)_mask;
        }

        Reference = 0;
        CanSet = true;
        Children = null;
    }

    public string Name { get; }
    public string? Type { get; }
    public long Reference { get; }
    public bool CanSet { get; }
    public bool IsViewOfParent => true;
    public IReadOnlyDictionary<string, IVariable>? Children { get; }
    public IVariable Parent => _treeParent;

    public void Evaluate(VariableContext context)
    {
        _parent.Evaluate(context);
    }

    public string Get(VariableContext context)
    {
        var value = (_parent.GetUInt() >> _offset) & _mask;

        return this.Format(value, context);
    }

    private string Format(uint value, VariableContext context)
    {
        return _subtype switch
        {
            DebuggerVariableType.ByteU or DebuggerVariableType.ShortU => FormattingUtils.FormatVariable(value, context),
            DebuggerVariableType.ByteS => FormattingUtils.FormatVariable((int)unchecked((sbyte)value), context),
            DebuggerVariableType.CharAscii => $"'{(char)value}'",
            DebuggerVariableType.ShortS => FormattingUtils.FormatVariable((int)unchecked((short)value), context),
            _ => throw new Exception("Invalid state.")
        };
    }

    public void Set(string value, VariableContext context)
    {
        uint shifted;

        if (_subtype == DebuggerVariableType.CharAscii)
        {
            if (value.Length != 1)
                throw new InvalidVariableFormatException("Invalid format. Expected an ASCII char.");

            var c = value[0];

            if (c < 0 || c > 255)
                throw new InvalidVariableFormatException("Invalid format. Expected an ASCII char.");

            shifted = ((uint)c) << _offset;
        }
        else
        {
            var parsed = FormattingUtils.ParseNumber32U(value, context.CultureInfo);
            var parsedI = unchecked((int)parsed);

            if (parsedI < _min || parsedI > _max)
                throw new InvalidVariableFormatException(
                    $"Invalid format. The number must be between {_min} and {_max}.");

            shifted = (parsed & _mask) << _offset;
        }

        _parent.Evaluate(context);
        var newValue = (_parent.GetUInt() & ~(_mask << _offset)) | shifted;
        _parent.SetUInt(newValue, context);
    }

    #region ITraceable

    public bool NeedsExplicitEvaluationAfterStep => _parent.NeedsExplicitEvaluationAfterStep;
    public bool CanPersist => _parent.CanPersist;

    private ITraceObserver? _traceObserver;
    private long _traceId;

    public void InitTrace(ExecutionEngine engine, ITraceObserver observer, long traceId)
    {
        if (_traceObserver != null && observer != _traceObserver)
            throw new NotImplementedException(
                "UIntBackedSubtypeAtomicVariable currently doesn't support more than one observer.");

        _traceObserver = observer;
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
            throw new NotImplementedException(
                "UIntBackedSubtypeAtomicVariable currently doesn't support more than one observer.");

        _traceObserver = null;
        _parent.StopTrace(engine, this);
    }

    internal void SetTrace(uint originalValue, uint newValue)
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

    public void TraceTriggered(long traceId, string? oldValue, string? newValue)
    {
        // Intentionally left blank: the value will be updated by UIntBackedVariable directly
    }

    #endregion
}
