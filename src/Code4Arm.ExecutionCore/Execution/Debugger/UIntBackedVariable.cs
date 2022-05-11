// UIntVariable.cs
// Author: Ondřej Ondryáš

using System.Runtime.CompilerServices;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public abstract class UIntBackedVariable : IVariable
{
    protected readonly Dictionary<string, IVariable> ChildrenInternal = new();
    protected uint CurrentValue;

    public abstract string Name { get; }
    public abstract string? Type { get; }
    public abstract long Reference { get; }
    public bool CanSet => true;
    public virtual IReadOnlyDictionary<string, IVariable> Children => ChildrenInternal;


    public abstract void SetUInt(uint value, VariableContext context);
    public abstract void Evaluate(VariableContext context);

    public uint GetUInt()
    {
        return CurrentValue;
    }

    public virtual string Get(VariableContext context)
    {
        var value = this.GetUInt();

        return FormattingUtils.FormatVariable(value, context);
    }

    public void Set(string value, VariableContext context)
    {
        var number = FormattingUtils.ParseNumber32U(value, context.CultureInfo);
        this.SetUInt(number, context);
    }
}

public class UIntBackedSubtypeVariable : IVariable
{
    private readonly UIntBackedVariable _parent;
    private readonly Subtype _subtype;

    public UIntBackedSubtypeVariable(UIntBackedVariable parent, Subtype subtype, long reference)
    {
        if (subtype is Subtype.LongU or Subtype.LongS or Subtype.Double)
            throw new ArgumentOutOfRangeException(nameof(subtype), subtype, null);

        _parent = parent;
        _subtype = subtype;

        Name = subtype switch
        {
            Subtype.ByteU => "unsigned bytes",
            Subtype.ByteS => "signed bytes",
            Subtype.CharAscii => "chars",
            Subtype.ShortU => "unsigned shorts",
            Subtype.ShortS => "signed shorts",
            Subtype.IntU => "unsigned int",
            Subtype.IntS => "signed int",
            Subtype.Float => "float",
            _ => throw new ArgumentOutOfRangeException(nameof(subtype), subtype, null)
        };

        Type = null;
        CanSet = subtype is Subtype.IntU or Subtype.IntS or Subtype.Float;
        Reference = reference;
        Children = null;

        if (!CanSet)
        {
            var c = new Dictionary<string, IVariable>();
            var count = (subtype is Subtype.ByteU or Subtype.ByteS or Subtype.CharAscii) ? 4 : 2;
            for (var i = 0; i < count; i++)
            {
                var child = new UIntBackedSubtypeAtomicVariable(parent, subtype, i);
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
    public IReadOnlyDictionary<string, IVariable>? Children { get; }

    public void Evaluate(VariableContext context)
    {
        _parent.Evaluate(context);
    }

    public string Get(VariableContext context)
    {
        if (_subtype is Subtype.ByteU or Subtype.ByteS or Subtype.CharAscii or Subtype.ShortU or Subtype.ShortS)
            return string.Empty;

        var value = _parent.GetUInt();

        return _subtype switch
        {
            Subtype.IntU => FormattingUtils.FormatVariable(value, context),
            Subtype.IntS => FormattingUtils.FormatVariable(unchecked((int)value), context),
            Subtype.Float => Unsafe.As<uint, float>(ref value).ToString(context.CultureInfo),
            _ => string.Empty
        };
    }

    public void Set(string value, VariableContext context)
    {
        var number = FormattingUtils.ParseNumber32U(value, context.CultureInfo);
        _parent.SetUInt(number, context);
    }
}

public class UIntBackedSubtypeAtomicVariable : IVariable
{
    private readonly UIntBackedVariable _parent;
    private readonly Subtype _subtype;

    private readonly uint _mask;
    private readonly int _maskI;
    private readonly int _offset;

    public UIntBackedSubtypeAtomicVariable(UIntBackedVariable parent, Subtype subtype, int index)
    {
        if (subtype is Subtype.IntU or Subtype.IntS or Subtype.LongU or Subtype.LongS or Subtype.Double)
            throw new ArgumentOutOfRangeException(nameof(subtype), subtype, null);

        _parent = parent;
        _subtype = subtype;

        Name = $"[{index}]";
        Type = subtype switch
        {
            Subtype.ByteU => "unsigned byte",
            Subtype.ByteS => "signed byte",
            Subtype.CharAscii => "char",
            Subtype.ShortU => "unsigned short",
            Subtype.ShortS => "signed short",
            _ => throw new ArgumentOutOfRangeException(nameof(subtype), subtype, null)
        };

        if (subtype is Subtype.ByteU or Subtype.ByteS or Subtype.CharAscii)
        {
            _mask = 0xFF;
            _maskI = 0xFF;
            _offset = 8 * index;
        }
        else
        {
            _mask = 0xFFFF;
            _maskI = 0xFFFF;
            _offset = 16 * index;
        }

        Reference = 0;
        CanSet = true;
        Children = null;
    }

    public string Name { get; }
    public string? Type { get; }
    public long Reference { get; }
    public bool CanSet { get; }
    public IReadOnlyDictionary<string, IVariable>? Children { get; }

    public void Evaluate(VariableContext context)
    {
        _parent.Evaluate(context);
    }

    public string Get(VariableContext context)
    {
        var value = (_parent.GetUInt() >> _offset) & _mask;

        return _subtype switch
        {
            Subtype.ByteU or Subtype.ShortU => FormattingUtils.FormatVariable(value, context),
            Subtype.ByteS => FormattingUtils.FormatVariable((int)unchecked((sbyte)value), context),
            Subtype.CharAscii => $"'{(char)value}'",
            Subtype.ShortS => FormattingUtils.FormatVariable((int)unchecked((short)value), context),
            _ => throw new Exception()
        };
    }

    public void Set(string value, VariableContext context)
    {
        uint shifted;

        if (_subtype == Subtype.CharAscii)
        {
            if (value.Length != 1)
                throw new FormatException();

            var c = value[0];

            if (c < 0 || c > 255)
                throw new FormatException();

            shifted = ((uint)c) << _offset;
        }
        else
        {
            var parsed = FormattingUtils.ParseNumber32S(value, context.CultureInfo);

            if (_subtype is Subtype.ByteU or Subtype.ShortU && parsed < 0)
                throw new FormatException();

            var masked = parsed & _maskI;

            if (masked != parsed)
                throw new FormatException();

            shifted = ((uint)masked) << _offset;
        }

        _parent.Evaluate(context);
        var newValue = (_parent.GetUInt() & ~(_mask << _offset)) | shifted;
        _parent.SetUInt(newValue, context);
    }
}
