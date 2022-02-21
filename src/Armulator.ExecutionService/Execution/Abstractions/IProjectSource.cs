// IProjectSource.cs
// Author: Ondřej Ondryáš

namespace Armulator.ExecutionService.Execution.Abstractions;

public interface IProjectSource
{
    string? Source { get; }

    ReadOnlyMemory<byte>? AssembledCode { get; }
    ReadOnlyMemory<byte>? AssembledData { get; }

    int AssembledCodeLength { get; }
    int AssembledDataLength { get; }

    void Assemble(string source, ref uint codeAddress, ref uint dataAddress);
}
