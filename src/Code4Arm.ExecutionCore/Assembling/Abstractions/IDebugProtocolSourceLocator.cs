// IDebugProtocolSourceLocator.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Code4Arm.ExecutionCore.Protocol.Models;

namespace Code4Arm.ExecutionCore.Assembling.Abstractions;

public interface IDebugProtocolSourceLocator
{
    IEnumerable<Source> Sources { get; }
    string GetCompilationPathForSource(Source source);

    /// <returns>The corresponding <see cref="AssembledObject"/>, or null if no such object exists.</returns>
    AssembledObject? GetObjectForSource(Source source);
}
