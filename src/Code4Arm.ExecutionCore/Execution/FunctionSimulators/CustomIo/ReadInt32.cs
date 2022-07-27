// ReadInt32.cs
// Author: Ondřej Ondryáš

using System.Globalization;
using Code4Arm.ExecutionCore.Execution.Debugger;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators.CustomIo;

public class ReadInt32 : ReadCommon32<int>
{
    protected override bool TryGetValue(string value, out int val)
        => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture,
            out val);

    public ReadInt32() : base("ReadInt32", -1)
    {
    }
}

public class ReadUInt32 : ReadCommon32<uint>
{
    protected override bool TryGetValue(string value, out uint val)
    {
        ReadOnlySpan<char> span;
        var numberStyle = NumberStyles.Integer;

        var binary = FormattingUtils.IsBinaryNumber(value, out var bS);
        var hS = value.StartsWith("0x");
        var hE = value.EndsWith("x") || value.EndsWith("h");

        if (binary)
        {
            try
            {
                val = FormattingUtils.ParseBinary32(value[bS ? (2..) : (..^1)]);

                return true;
            }
            catch
            {
                val = 0;

                return false;
            }
        }

        if (hS || hE)
        {
            span = value.AsSpan()[hS ? (2..) : (..^1)];
            numberStyle = NumberStyles.HexNumber;
        }
        else
        {
            span = value.AsSpan();
        }

        return uint.TryParse(span, numberStyle, CultureInfo.InvariantCulture, out val);
    }

    public ReadUInt32() : base("ReadUInt32", uint.MaxValue)
    {
    }
}

public class ReadFloat32 : ReadCommon32<float>
{
    protected override bool TryGetValue(string value, out float val)
        => float.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out val);

    public ReadFloat32() : base("ReadFloat32", float.NaN)
    {
    }
}

public class ReadInt64 : ReadCommon64<long>
{
    protected override bool TryGetValue(string value, out long val)
        => long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out val);

    public ReadInt64() : base("ReadInt64", -1)
    {
    }
}

public class ReadUInt64 : ReadCommon64<ulong>
{
    protected override bool TryGetValue(string value, out ulong val)
    {
        ReadOnlySpan<char> span;
        var numberStyle = NumberStyles.Integer;

        var binary = FormattingUtils.IsBinaryNumber(value, out var bS);
        var hS = value.StartsWith("0x");
        var hE = value.EndsWith("x") || value.EndsWith("h");

        if (binary)
        {
            try
            {
                val = FormattingUtils.ParseBinary32(value[bS ? (2..) : (..^1)]);

                return true;
            }
            catch
            {
                val = 0;

                return false;
            }
        }

        if (hS || hE)
        {
            span = value.AsSpan()[hS ? (2..) : (..^1)];
            numberStyle = NumberStyles.HexNumber;
        }
        else
        {
            span = value.AsSpan();
        }

        return ulong.TryParse(span, numberStyle, CultureInfo.InvariantCulture, out val);
    }

    public ReadUInt64() : base("ReadUInt64", ulong.MaxValue)
    {
    }
}

public class ReadFloat64 : ReadCommon64<double>
{
    protected override bool TryGetValue(string value, out double val)
        => double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out val);

    public ReadFloat64() : base("ReadFloat64", double.NaN)
    {
    }
}
