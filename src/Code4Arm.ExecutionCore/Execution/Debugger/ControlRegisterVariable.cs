// ControlRegisterVariable.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public readonly struct ControlRegisterFlag
{
    public readonly int LowBitIndex;
    public readonly int Length;
    public readonly string Name;
    public readonly string Description;
    public readonly string[]? Values;

    public ControlRegisterFlag(int lowBitIndex, int length, string name, string description, params string[] values)
    {
        LowBitIndex = lowBitIndex;
        Length = length;
        Name = name;
        Description = description;
        Values = values.Length == 0 ? null : values;
    }

    public ControlRegisterFlag(int lowBitIndex, string name, string description, params string[] values)
    {
        LowBitIndex = lowBitIndex;
        Length = 1;
        Name = name;
        Description = description;
        Values = values.Length == 0 ? null : values;
    }
}

public class ControlRegisterVariable : IVariable
{
    private readonly int _unicornRegisterId;
    private uint _currentValue;

    public ControlRegisterVariable(int unicornRegisterId, string name, string type, params ControlRegisterFlag[] flags)
    {
        _unicornRegisterId = unicornRegisterId;

        Name = name;
        Type = type;
        Reference = ReferenceUtils.MakeReference(ContainerType.ControlFlags, unicornRegisterId);
        CanSet = true;

        var children = new Dictionary<string, IVariable>();
        foreach (var flag in flags)
        {
            var flagVariable = new FlagVariable(this, flag);
            children.Add(flagVariable.Name, flagVariable);
        }

        Children = children;
    }

    public string Name { get; }
    public string? Type { get; }
    public long Reference { get; }
    public bool CanSet { get; }
    public bool IsViewOfParent => false;
    public IReadOnlyDictionary<string, IVariable>? Children { get; }
    public IVariable? Parent => null;
    
    public void Evaluate(VariableContext context)
    {
        _currentValue = context.Engine.Engine.RegRead<uint>(_unicornRegisterId);
    }

    public uint Value => _currentValue;

    public void Set(uint value, VariableContext context)
    {
        context.Engine.Engine.RegWrite(_unicornRegisterId, value);
    }

    public string Get(VariableContext context)
    {
        return $"0x{Value:x}";
    }

    public void Set(string value, VariableContext context)
    {
        var number = FormattingUtils.ParseNumber32U(value, context.CultureInfo);
        context.Engine.Engine.RegWrite(_unicornRegisterId, number);
    }
}

public class FlagVariable : IVariable
{
    private readonly ControlRegisterVariable _parent;
    private readonly ControlRegisterFlag _flag;
    private readonly uint _mask;

    public FlagVariable(ControlRegisterVariable parent, ControlRegisterFlag flag)
    {
        _parent = parent;
        _flag = flag;
        _mask = unchecked((uint)((1 << flag.Length) - 1));

        Reference = 0;
        CanSet = true;
        Children = null;
    }

    public string Name => _flag.Name;
    public string Type => _flag.Description;
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
        var val = (_parent.Value >> _flag.LowBitIndex) & _mask;

        if (_flag.Values != null && _flag.Values.Length > val)
            return _flag.Values[val];

        return Convert.ToString(val, 2);
    }

    public void Set(string value, VariableContext context)
    {
        uint valU = 0;

        try
        {
            valU = Convert.ToUInt32(value, 2);
        }
        catch (FormatException)
        {
            var continueSearch = true;
            if (_flag.Values != null)
            {
                for (var i = 0; i < _flag.Values.Length; i++)
                {
                    if (_flag.Values[i].Equals(value, StringComparison.OrdinalIgnoreCase))
                    {
                        valU = (uint)i;
                        continueSearch = false;

                        break;
                    }
                }
            }

            if (continueSearch)
                valU = FormattingUtils.ParseNumber32U(value, context.CultureInfo);
        }

        if (valU > _mask)
            throw new InvalidVariableFormatException($"Invalid format. The maximum value is {_mask:x}.");

        _parent.Evaluate(context);
        var currentVal = _parent.Value;
        var newVal = (currentVal & ~(_mask << _flag.LowBitIndex)) | (valU << _flag.LowBitIndex);
        _parent.Set(newVal, context);
    }
}
