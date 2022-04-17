// ICodeExecutionInfo.cs
// Author: Ondřej Ondryáš

using OmniSharp.Extensions.DebugAdapter.Protocol.Models;
using OmniSharp.Extensions.DebugAdapter.Protocol.Requests;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public interface ICodeExecutionInfo
{
    IEnumerable<DataBreakpointInfoResponse> GetDataBreakpointInfo(string name);
    EvaluateResponse EvaluateExpression(EvaluateArguments arguments);
    ExceptionInfoResponse GetLastExceptionInfo();
    IEnumerable<GotoTarget> GetGotoTargets(GotoTargetsArguments arguments);
    public uint StackStartAddress { get; }
    public uint StackSize { get; }
    public uint StackTopAddress { get; }
    public uint StackEndAddress { get; }
}
