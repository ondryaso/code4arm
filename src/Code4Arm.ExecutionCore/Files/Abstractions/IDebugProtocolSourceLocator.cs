// IDebugProtocolSourceLocator.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Protocol.Models;

namespace Code4Arm.ExecutionCore.Files.Abstractions;

public interface IDebugProtocolSourceLocator
{
    ValueTask<Source> GetSourceForFile(IAsmFile asmFile);
    ValueTask<IAsmFile> GetFileForSource(Source source);
}
