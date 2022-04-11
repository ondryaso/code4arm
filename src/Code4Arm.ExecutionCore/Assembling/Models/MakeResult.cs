// MakeResult.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Files.Abstractions;

namespace Code4Arm.ExecutionCore.Assembling.Models;

public enum MakeResultState
{
    Successful,
    InvalidObjects,
    LinkingError
}

public record struct MakeResult(IAsmProject Project, MakeResultState State, Executable? Executable,
    List<AssembledObject> ValidObjects, List<AssembledObject>? InvalidObjects, string? LinkerError);
