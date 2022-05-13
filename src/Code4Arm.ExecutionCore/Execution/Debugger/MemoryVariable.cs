// MemoryVariable.cs
// Author: Ondřej Ondryáš

using System.Numerics;
using Code4Arm.Unicorn.Abstractions.Extensions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class MemoryVariable : IVariable
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

    public string Get(VariableContext context) => _value ?? string.Empty;

    public void Set(string value, VariableContext context)
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
}
