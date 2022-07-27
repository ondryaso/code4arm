// ReadCommon.cs
// Author: Ondřej Ondryáš

using System.Runtime.InteropServices;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.ExecutionStateFeatures;
using Code4Arm.Unicorn.Constants;

namespace Code4Arm.ExecutionCore.Execution.FunctionSimulators.CustomIo;

public abstract class ReadCommon32<TVal> : IFunctionSimulator where TVal : unmanaged
{
    private readonly TVal _defaultValue;
    public string Name { get; }

    public ReadCommon32(string name, TVal defaultValue)
    {
        Name = name;
        _defaultValue = defaultValue;
    }

    protected abstract bool TryGetValue(string value, out TVal val);

    public void Run(IExecutionEngine engine)
    {
        var input = engine.WaitForEmulatedInputLine();
        var errno = engine.GetStateFeature<ErrnoFeature>();

        if (this.TryGetValue(input, out var val))
        {
            engine.Engine.RegWrite(Arm.Register.R0, val);
            errno?.SetErrno(0);
        }
        else
        {
            engine.Engine.RegWrite(Arm.Register.R0, _defaultValue);
            errno?.SetErrno(22); // EINVAL
        }
    }
}

public abstract class ReadCommon64<TVal> : IFunctionSimulator where TVal : unmanaged
{
    private readonly TVal _defaultValue;
    public string Name { get; }

    public ReadCommon64(string name, TVal defaultValue)
    {
        Name = name;
        _defaultValue = defaultValue;
    }

    protected abstract bool TryGetValue(string value, out TVal val);

    public void Run(IExecutionEngine engine)
    {
        var input = engine.WaitForEmulatedInputLine();
        var errno = engine.GetStateFeature<ErrnoFeature>();

        if (this.TryGetValue(input, out var val))
        {
            errno?.SetErrno(0);
        }
        else
        {
            val = _defaultValue;
            errno?.SetErrno(22); // EINVAL
        }

        var uintSpan = MemoryMarshal.Cast<TVal, uint>(MemoryMarshal.CreateReadOnlySpan(ref val, 1));
        if (uintSpan.Length != 2)
        {
            engine.Engine.RegWrite(Arm.Register.R0, 0);
        }
        else
        {
            var le = BitConverter.IsLittleEndian;
            engine.Engine.RegWrite(Arm.Register.R0, uintSpan[le ? 1 : 0]);
            engine.Engine.RegWrite(Arm.Register.R1, uintSpan[le ? 0 : 1]);
        }
    }
}
