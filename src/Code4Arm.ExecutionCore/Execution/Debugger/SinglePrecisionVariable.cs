// SinglePrecisionVariable.cs
// Author: Ondřej Ondryáš

using System.Runtime.CompilerServices;
using Code4Arm.ExecutionCore.Execution.Exceptions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public enum IeeeSegment
{
    Sign,
    Exponent,
    Mantissa
}

public class SinglePrecisionIeeeSegmentVariable : IVariable
{
    private readonly ISettableBackedVariable<float> _parent;
    private readonly IeeeSegment _segment;

    private readonly uint _mask;
    private readonly int _shift;

    public SinglePrecisionIeeeSegmentVariable(ISettableBackedVariable<float> parent, IeeeSegment segment)
    {
        _parent = parent;
        _segment = segment;

        switch (segment)
        {
            case IeeeSegment.Sign:
                _mask = 0x80000000;
                _shift = 31;

                break;
            case IeeeSegment.Exponent:
                _mask = 0x7F800000;
                _shift = 23;

                break;
            case IeeeSegment.Mantissa:
                _mask = 0x007FFFFF;
                _shift = 0;

                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(segment), segment, null);
        }

        Name = segment.ToString().ToLowerInvariant();
        Type = Name;
        Reference = 0;
        CanSet = _parent.CanSet;
    }

    public string Name { get; }
    public string? Type { get; }
    public long Reference { get; }
    public bool CanSet { get; }
    public bool IsViewOfParent => true;
    public IReadOnlyDictionary<string, IVariable>? Children => null;
    public IVariable Parent => _parent;

    public void Evaluate(VariableContext context)
    {
        _parent.Evaluate(context);
    }

    public string Get(VariableContext context)
    {
        var value = _parent.GetBackingValue(context);
        var valueRaw = Unsafe.As<float, uint>(ref value);
        valueRaw = (valueRaw & _mask) >> _shift;

        switch (_segment)
        {
            case IeeeSegment.Sign:
                // Just a 0 or 1
                return valueRaw == 1 ? "1 (-)" : "0 (+)";
            case IeeeSegment.Exponent:
                return valueRaw switch
                {
                    0 => "00000000 => zero/subnormal",
                    255 => "11111111 => inf/NaN",
                    _ => $"{Convert.ToString(valueRaw, 2).PadLeft(8, '0')} => {(int)valueRaw - 127}"
                };
            case IeeeSegment.Mantissa:
                return $"{Convert.ToString(valueRaw, 2).PadLeft(23, '0')} => {valueRaw}";
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    public void Set(string value, VariableContext context)
    {
        uint valU;

        if (_segment == IeeeSegment.Sign)
        {
            valU = value switch
            {
                "+" or "0" => 0,
                "-" or "1" => 1,
                _ => throw new InvalidVariableFormatException($"Invalid format. Only 0/1 or +/- is accepted.")
            };
        }
        else
        {
            valU = FormattingUtils.ParseNumber32U(value, context.CultureInfo);

            if (_segment == IeeeSegment.Exponent && !value.StartsWith("0b")) // exp is in biased encoding
                valU += 127;
        }

        var max = _mask >> _shift;

        if (valU > max)
            if (_segment == IeeeSegment.Exponent)
                throw new InvalidVariableFormatException($"Invalid format. The value must be between -127 and 128.");
            else
                throw new InvalidVariableFormatException($"Invalid format. The maximum value is {max}.");

        _parent.Evaluate(context);

        var currentVal = _parent.GetBackingValue(context);
        var currentValU = Unsafe.As<float, uint>(ref currentVal);
        var newValU = (currentValU & ~_mask) | (valU << _shift);
        var newVal = Unsafe.As<uint, float>(ref newValU);

        _parent.Set(newVal, context);
    }
}

public class DoublePrecisionIeeeSegmentVariable : IVariable
{
    private readonly ISettableBackedVariable<double> _parent;
    private readonly IeeeSegment _segment;

    private readonly ulong _mask;
    private readonly int _shift;

    public DoublePrecisionIeeeSegmentVariable(ISettableBackedVariable<double> parent, IeeeSegment segment)
    {
        _parent = parent;
        _segment = segment;

        switch (segment)
        {
            case IeeeSegment.Sign:
                _mask = 0x1ul << 63;
                _shift = 63;

                break;
            case IeeeSegment.Exponent:
                _mask = 0x7FFul << 52;
                _shift = 52;

                break;
            case IeeeSegment.Mantissa:
                _mask = ~(0xFFFul << 52);
                _shift = 0;

                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(segment), segment, null);
        }

        Name = segment.ToString().ToLowerInvariant();
        Type = Name;
        Reference = 0;
        CanSet = _parent.CanSet;
    }

    public string Name { get; }
    public string? Type { get; }
    public long Reference { get; }
    public bool CanSet { get; }
    public bool IsViewOfParent => true;
    public IReadOnlyDictionary<string, IVariable>? Children => null;
    public IVariable Parent => _parent;

    public void Evaluate(VariableContext context)
    {
        _parent.Evaluate(context);
    }

    public string Get(VariableContext context)
    {
        var value = _parent.GetBackingValue(context);
        var valueRaw = Unsafe.As<double, ulong>(ref value);
        valueRaw = (valueRaw & _mask) >> _shift;
        var valueRawLong = Unsafe.As<ulong, long>(ref valueRaw);

        switch (_segment)
        {
            case IeeeSegment.Sign:
                // Just a 0 or 1
                return valueRaw == 1 ? "1 (-)" : "0 (+)";
            case IeeeSegment.Exponent:
                return valueRaw switch
                {
                    0 => "00000000 => zero/subnormal",
                    255 => "11111111 => inf/NaN",
                    _ => $"{Convert.ToString(valueRawLong, 2).PadLeft(11, '0')} => {(int)valueRaw - 1023}"
                };
            case IeeeSegment.Mantissa:
                return $"{Convert.ToString(valueRawLong, 2).PadLeft(52, '0')} => {valueRaw}";
            default:
                throw new ArgumentOutOfRangeException();
        }
    }

    public void Set(string value, VariableContext context)
    {
        ulong valU;

        if (_segment == IeeeSegment.Sign)
        {
            valU = value switch
            {
                "+" or "0" => 0,
                "-" or "1" => 1,
                _ => throw new InvalidVariableFormatException($"Invalid format. Only 0/1 or +/- is accepted.")
            };
        }
        else
        {
            valU = FormattingUtils.ParseNumber64U(value, context.CultureInfo);

            if (_segment == IeeeSegment.Exponent && !value.StartsWith("0b")) // exp is in biased encoding
                valU += 1023;
        }

        var max = _mask >> _shift;

        if (valU > max)
            if (_segment == IeeeSegment.Exponent)
                throw new InvalidVariableFormatException($"Invalid format. The value must be between -1023 and 1024.");
            else
                throw new InvalidVariableFormatException($"Invalid format. The maximum value is {max}.");

        _parent.Evaluate(context);

        var currentVal = _parent.GetBackingValue(context);
        var currentValU = Unsafe.As<double, ulong>(ref currentVal);
        var newValU = (currentValU & ~_mask) | (valU << _shift);
        var newVal = Unsafe.As<ulong, double>(ref newValU);

        _parent.Set(newVal, context);
    }
}
