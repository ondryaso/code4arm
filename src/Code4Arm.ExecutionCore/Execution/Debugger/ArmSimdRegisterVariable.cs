// ArmSimdRegisterVariable.cs
// Author: Ondřej Ondryáš

using System.Globalization;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class ArmQSimdRegisterVariable : IVariable
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
        return Values[1] == 0
            ? $"0x{Values[0]:x}"
            : $"0x{Values[1]:x}{Values[0]:x}";
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
            throw new FormatException();

        var valuesSpan = MemoryMarshal.Cast<ulong, byte>(Values);
        valuesSpan.Clear();
        i.TryWriteBytes(valuesSpan, out _);

        context.Engine.Engine.RegWrite(_unicornRegId, valuesSpan);
    }
}

public class ArmDSimdRegisterVariable : IVariable
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
        var toRet = Value;
        if (context.Options.ShowSimdRegistersAsFp)
        {
            var d = Unsafe.As<ulong, double>(ref toRet);

            return d.ToString(context.CultureInfo);
        }

        return $"0x{toRet:x}";
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
