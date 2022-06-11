// ULongBackedSubvariables.cs
// Author: Ondřej Ondryáš

using System.Runtime.CompilerServices;
using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class ULongBackedSubtypeVariable<TParent> : ULongBackedDependentTraceable, IVariable
    where TParent : ISettableBackedVariable<ulong>, ITraceable
{
    private readonly TParent _parent;
    private readonly DebuggerVariableType _subtype;

    internal ULongBackedSubtypeVariable(TParent parent, DebuggerVariableType subtype, long reference,
        bool showIeeeSubvariables)
        : base(parent, ulong.MaxValue, 0)
    {
        _parent = parent;
        _subtype = subtype;

        Name = subtype switch
        {
            DebuggerVariableType.ByteU => "unsigned bytes",
            DebuggerVariableType.ByteS => "signed bytes",
            DebuggerVariableType.CharAscii => "chars",
            DebuggerVariableType.ShortU => "unsigned shorts",
            DebuggerVariableType.ShortS => "signed shorts",
            DebuggerVariableType.IntU => "unsigned ints",
            DebuggerVariableType.IntS => "signed ints",
            DebuggerVariableType.Float => "floats",
            DebuggerVariableType.LongU => "unsigned long",
            DebuggerVariableType.LongS => "unsigned long",
            DebuggerVariableType.Double => "double",
            _ => throw new ArgumentOutOfRangeException(nameof(subtype), subtype, null)
        };

        Type = null;
        CanSet = subtype is DebuggerVariableType.LongU or DebuggerVariableType.LongS or DebuggerVariableType.Double;
        Reference = reference;
        Children = null;

        if (!CanSet)
        {
            var c = new Dictionary<string, IVariable>();
            var count = 8 / subtype.GetSize();
            for (var i = 0; i < count; i++)
            {
                var child = new ULongBackedSubtypeAtomicVariable<TParent>(parent, this, subtype, i);
                c.Add(child.Name, child);
            }

            Children = c;
        }
        else if (subtype is DebuggerVariableType.Double && showIeeeSubvariables &&
                 parent is ISettableBackedVariable<double> doubleBackedParent)
        {
            var sign = new DoublePrecisionIeeeSegmentVariable(doubleBackedParent, IeeeSegment.Sign);
            var exp = new DoublePrecisionIeeeSegmentVariable(doubleBackedParent, IeeeSegment.Exponent);
            var mant = new DoublePrecisionIeeeSegmentVariable(doubleBackedParent, IeeeSegment.Mantissa);

            Children = new Dictionary<string, IVariable>()
                { { sign.Name, sign }, { exp.Name, exp }, { mant.Name, mant } };
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
        var value = _parent.GetBackingValue(context);

        return this.Format(value, context);
    }

    public void Set(string value, VariableContext context)
    {
        var number = _subtype == DebuggerVariableType.Float
            ? FormattingUtils.ParseNumber64F(value, context.CultureInfo)
            : FormattingUtils.ParseNumber64U(value, context.CultureInfo);

        _parent.Set(number, context);
    }

    protected override string Format(ulong value, VariableContext context)
    {
        if (_subtype is DebuggerVariableType.ByteU or DebuggerVariableType.ByteS or DebuggerVariableType.CharAscii
            or DebuggerVariableType.ShortU or DebuggerVariableType.ShortS or DebuggerVariableType.IntU
            or DebuggerVariableType.IntS)
            return string.Empty;

        return _subtype switch
        {
            DebuggerVariableType.LongU => FormattingUtils.FormatAnyVariable(value, context, 64, false),
            DebuggerVariableType.LongS => FormattingUtils.FormatAnyVariable(unchecked((long)value), context,
                64, unchecked((long)value) < 0),
            DebuggerVariableType.Double => Unsafe.As<ulong, double>(ref value).ToString(context.CultureInfo),
            _ => string.Empty
        };
    }
}

public class ULongBackedSubtypeAtomicVariable<TParent> : ULongBackedDependentTraceable, IVariable,
                                                         ISettableBackedVariable<float>
    where TParent : ISettableBackedVariable<ulong>, ITraceable
{
    private readonly TParent _parent;
    private readonly IVariable _treeParent;
    private readonly DebuggerVariableType _subtype;

    private readonly ulong _mask;
    private readonly int _offset;

    private readonly long _min, _max;

    internal ULongBackedSubtypeAtomicVariable(TParent parent, IVariable treeParent,
        DebuggerVariableType subtype, int index)
        : base(parent, subtype switch
        {
            DebuggerVariableType.ByteU or DebuggerVariableType.ByteS or DebuggerVariableType.CharAscii => 0xFF,
            DebuggerVariableType.ShortS or DebuggerVariableType.ShortU => 0xFFFF,
            _ => 0xFFFFFFFF
        }, subtype switch
        {
            DebuggerVariableType.ByteU or DebuggerVariableType.ByteS or DebuggerVariableType.CharAscii => 8 * index,
            DebuggerVariableType.ShortS or DebuggerVariableType.ShortU => 16 * index,
            _ => 32 * index
        })
    {
        if (subtype is DebuggerVariableType.LongU or DebuggerVariableType.LongS or DebuggerVariableType.Double)
            throw new ArgumentOutOfRangeException(nameof(subtype), subtype, null);

        // TODO: Support for IEEE

        _parent = parent;
        _treeParent = treeParent;
        _subtype = subtype;

        Name = $"[{index}]";
        Type = subtype.GetName();

        if (subtype is DebuggerVariableType.ByteU or DebuggerVariableType.ByteS or DebuggerVariableType.CharAscii)
        {
            _mask = 0xFF;
            _offset = 8 * index;
        }
        else if (subtype is DebuggerVariableType.ShortS or DebuggerVariableType.ShortU)
        {
            _mask = 0xFFFF;
            _offset = 16 * index;
        }
        else
        {
            _mask = 0xFFFFFFFF;
            _offset = 32 * index;
        }

        if (subtype is DebuggerVariableType.ByteS or DebuggerVariableType.ShortS or DebuggerVariableType.IntS)
        {
            _min = -((long)_mask / 2) - 1;
            _max = (long)_mask / 2;
        }
        else if (subtype is DebuggerVariableType.Float)
        {
            _min = long.MinValue;
            _max = long.MaxValue;
        }
        else
        {
            _min = 0;
            _max = (long)_mask;
        }

        Reference = 0;
        CanSet = true;
        Children = null;
    }

    public float GetBackingValue(VariableContext context)
    {
        if (_subtype != DebuggerVariableType.Float)
            throw new InvalidOperationException();

        var value = (_parent.GetBackingValue(context) >> _offset) & _mask;

        return Unsafe.As<ulong, float>(ref value);
    }

    public void Set(float value, VariableContext context)
    {
        var valueU = (ulong)Unsafe.As<float, uint>(ref value);
        var shifted = (valueU & _mask) << _offset;

        _parent.Evaluate(context);
        var newValue = (_parent.GetBackingValue(context) & ~(_mask << _offset)) | shifted;
        _parent.Set(newValue, context);
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
        var value = (_parent.GetBackingValue(context) >> _offset) & _mask;

        return this.Format(value, context);
    }

    protected override string Format(ulong value, VariableContext context)
    {
        return _subtype switch
        {
            DebuggerVariableType.ByteU or DebuggerVariableType.ShortU or DebuggerVariableType.IntU
                => FormattingUtils.FormatVariable((uint)value, context, _subtype.GetSize() * 8),
            DebuggerVariableType.ByteS => FormattingUtils.FormatSignedVariable(unchecked((sbyte)value), context, 8),
            DebuggerVariableType.CharAscii => $"'{(char)value}'",
            DebuggerVariableType.ShortS => FormattingUtils.FormatSignedVariable(unchecked((short)value), context,
                16),
            DebuggerVariableType.IntS => FormattingUtils.FormatSignedVariable(unchecked((int)value), context, 32),
            DebuggerVariableType.Float => Unsafe.As<ulong, float>(ref value).ToString(context.CultureInfo),
            _ => throw new Exception("Invalid state.")
        };
    }

    public void Set(string value, VariableContext context)
    {
        ulong shifted;

        if (_subtype == DebuggerVariableType.CharAscii)
        {
            if (value.Length != 1)
                throw new InvalidVariableFormatException("Invalid format. Expected an ASCII char.");

            var c = value[0];

            if (c < 0 || c > 255)
                throw new InvalidVariableFormatException("Invalid format. Expected an ASCII char.");

            shifted = ((ulong)c) << _offset;
        }
        else
        {
            var parsed = _subtype == DebuggerVariableType.Float
                ? FormattingUtils.ParseNumber32U(value, context.CultureInfo)
                : FormattingUtils.ParseNumber64U(value, context.CultureInfo);

            var parsedI = unchecked((long)parsed);

            if (parsedI < _min || parsedI > _max)
                throw new InvalidVariableFormatException(
                    $"Invalid format. The number must be between {_min} and {_max}.");

            shifted = (parsed & _mask) << _offset;
        }

        _parent.Evaluate(context);
        var newValue = (_parent.GetBackingValue(context) & ~(_mask << _offset)) | shifted;
        _parent.Set(newValue, context);
    }
}
