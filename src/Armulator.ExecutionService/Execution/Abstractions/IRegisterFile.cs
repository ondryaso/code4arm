// IRegisterFile.cs
// Author: Ondřej Ondryáš

namespace Armulator.ExecutionService.Execution.Abstractions;

public interface IRegisterFile<T> : IEnumerable<T> where T : struct, IComparable<T>
{
    int Count { get; }
    T this[int index] { get; set; }
}
