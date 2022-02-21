// IBreakpoint.cs
// Author: Ondřej Ondryáš

namespace Armulator.ExecutionService.Execution.Abstractions;

public interface IBreakpoint
{
    int Line { get; }
    bool IsException { get; }
    // In future: Conditions, Hit Count Conditions
}
