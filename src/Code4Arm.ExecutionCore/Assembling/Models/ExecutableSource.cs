// ExecutableSource.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Files.Abstractions;

namespace Code4Arm.ExecutionCore.Assembling.Models;

public record struct ExecutableSource(IAsmFile SourceFile, string BuildPath, int SourceVersion, string? ClientPath)
{
}
