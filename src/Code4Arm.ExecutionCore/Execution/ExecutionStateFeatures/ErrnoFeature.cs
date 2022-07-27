// ErrnoFeature.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.Unicorn.Abstractions.Extensions;
using ELFSharp.ELF.Sections;

namespace Code4Arm.ExecutionCore.Execution.ExecutionStateFeatures;

public class ErrnoFeature : IExecutionStateFeature
{
    private readonly ExecutionEngine _engine;
    private Executable? Executable => _engine.ExecutableInfo as Executable;

    public ErrnoFeature(ExecutionEngine engine)
    {
        _engine = engine;
    }

    public void SetErrno(int value)
    {
        if (Executable?.Elf.Sections.FirstOrDefault(s => s.Type == SectionType.SymbolTable) is not SymbolTable<uint>
            symTab)
            return;

        var errnoSymbol = symTab.Entries.FirstOrDefault(s => s.Name == "errno");

        if (errnoSymbol == null)
            return;

        _engine.Engine.MemWriteSafe(errnoSymbol.Value, value);
    }
}
