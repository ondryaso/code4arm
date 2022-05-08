// IDebugProtocolSourceLocator.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public interface IDebugProtocolSourceLocator
{
    Task<IEnumerable<Source>> GetSources();

    Task<SourceResponse> GetSourceContents(long sourceReference);
    Task<SourceResponse> GetSourceContents(Source source);

    string? GetCompilationPathForSource(Source source);

    /// <returns>The corresponding <see cref="AssembledObject"/>, or null if no such object exists.</returns>
    AssembledObject? GetObjectForSource(Source source);

    Task<SourceResponse> GetSourceContents(SourceArguments arguments)
        => arguments.Source is null
            ? this.GetSourceContents(arguments.SourceReference)
            : this.GetSourceContents(arguments.Source);
}
