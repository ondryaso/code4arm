// PoCInitialRegisterFile.cs
// Author: Ondřej Ondryáš

using System.Collections;
using Armulator.ExecutionService.Execution.Abstractions;

namespace Armulator.ExecutionService.Execution.ProofOfConcept;

public class PoCInitialRegisterFile<T> : IRegisterFile<T> where T : struct, IComparable<T>
{
    private T[] _registers = new T[16];

    public IEnumerator<T> GetEnumerator()
    {
        return ((IEnumerable<T>)_registers).GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return _registers.GetEnumerator();
    }

    public int Count => 16;

    public T this[int index]
    {
        get => _registers[index];
        set => _registers[index] = value;
    }
}
