// DebugProvider.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.Unicorn.Abstractions;

namespace Code4Arm.ExecutionCore.Execution;

internal class DebugProvider : IDebugProvider
{
    private readonly ExecutionEngine _engine;
    private readonly IUnicorn _unicorn;

    public DebugProvider(ExecutionEngine engine)
    {
        _engine = engine;
        _unicorn = engine.Engine;
    }

    public IEnumerable<GotoTarget> GetGotoTargets(Source source, long line, long? column) =>
        throw new NotImplementedException();

    public SetVariableResponse SetVariable(long containerId, string variableName, string value, ValueFormat? format) =>
        throw new NotImplementedException();

    public SourceResponse GetSource(long sourceReference) => throw new NotImplementedException();

    public SourceResponse GetSource(Source source) => throw new NotImplementedException();

    public IEnumerable<DataBreakpointInfoResponse> GetDataBreakpointInfo(string name) =>
        throw new NotImplementedException();

    public EvaluateResponse EvaluateExpression(string expression, EvaluateArgumentsContext? context,
        ValueFormat? format) => throw new NotImplementedException();

    public ExceptionInfoResponse GetLastExceptionInfo() => throw new NotImplementedException();

    public StackTraceResponse MakeStackTrace() => throw new NotImplementedException();

    public ScopesResponse MakeVariableScopes() => throw new NotImplementedException();

    public IEnumerable<BreakpointLocation> GetBreakpointLocations(Source source, int line, int? endLine) =>
        throw new NotImplementedException();

    public IEnumerable<DisassembledInstruction> Disassemble(string memoryReference, long? byteOffset,
        long? instructionOffset, long instructionCount,
        bool resolveSymbols) =>
        throw new NotImplementedException();
}
