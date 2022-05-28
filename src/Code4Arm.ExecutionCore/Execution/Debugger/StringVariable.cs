// StringVariable.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.Unicorn;
using Code4Arm.Unicorn.Abstractions.Extensions;

namespace Code4Arm.ExecutionCore.Execution.Debugger;

public class StringVariable : IVariable, IAddressBackedVariable
{
    private readonly uint _address;
    private string? _value;

    public StringVariable(string name, uint address)
    {
        _address = address;

        Name = name;
        Type = "null-terminated string";
        Reference = 0;
        CanSet = true;
        IsViewOfParent = false;
        Children = null;
        Parent = null;
    }

    public string Name { get; }
    public string? Type { get; }
    public long Reference { get; }
    public bool CanSet { get; }
    public bool IsViewOfParent { get; }
    public IReadOnlyDictionary<string, IVariable>? Children { get; }
    public IVariable? Parent { get; }

    public void Evaluate(VariableContext context)
    {
        try
        {
            _value = context.Engine.Engine.MemReadCString(_address, context.Options.CStringMaxLength, uint.MaxValue,
                context.Options.CStringEncoding);
        }
        catch (Exception e) when (e is OverflowException || (e is UnicornException uniE && uniE.Error.IsMemoryError()))
        {
            throw new InvalidMemoryOperationException(ExceptionMessages.InvalidMemoryRead, e);
        }
    }

    public string Get(VariableContext context) => _value ?? string.Empty;

    public void Set(string value, VariableContext context)
    {
        var encoding = context.Options.CStringEncoding;
        var byteCount = encoding.GetByteCount(value) + 1;

        try
        {
            if (byteCount < ExecutionEngine.MaxStackAllocatedSize)
            {
                Span<byte> bytes = stackalloc byte[byteCount];
                encoding.GetBytes(value.AsSpan(), bytes);
                bytes[^1] = 0;
                context.Engine.Engine.MemWrite(_address, bytes);
            }
            else
            {
                var bytes = new byte[byteCount];
                encoding.GetBytes(value.AsSpan(), bytes);
                bytes[^1] = 0;
                context.Engine.Engine.MemWrite(_address, bytes);
            }
        }
        catch (UnicornException e) when (e.Error.IsMemoryError())
        {
            throw new InvalidMemoryOperationException(ExceptionMessages.InvalidMemoryWrite, e);
        }
    }

    public uint GetAddress() => _address;
}
