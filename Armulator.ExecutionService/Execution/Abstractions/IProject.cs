// IProject.cs
// Author: Ondřej Ondryáš

namespace Armulator.ExecutionService.Execution.Abstractions;

public interface IProject
{
    // Metadata
    Guid Identifier { get; }
    string? Name { get; set; }
    DateTime Created { get; }
    DateTime Modified { get; }
    DateTime Accessed { get; }

    IProjectState InitialState { get; }
    IProjectSource Source { get; }

    IExecutionContext InitExecution();
}
