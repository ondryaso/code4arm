// IProjectSession.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Files.Abstractions;

namespace Code4Arm.ExecutionService.Services.Projects;

public interface IProjectSession : IAsmMakeTarget, IDisposable
{
    bool Dirty { get; }

    Task<MakeResult> Build(bool rebuild);

    Task Use(IExecutionEngine execution);

    Task<IDebugProtocolSourceLocator> GetSourceLocator();
}
