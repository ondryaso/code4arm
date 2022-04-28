// DebugProvider.cs
// Author: Ondřej Ondryáš

using System.Diagnostics.CodeAnalysis;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.Unicorn.Abstractions;

namespace Code4Arm.ExecutionCore.Execution;

internal class DebugProvider : IDebugProvider
{
    private readonly ExecutionEngine _engine;
    private readonly IUnicorn _unicorn;
    private InitializeRequestArguments? _clientInfo;

    public DebugProvider(ExecutionEngine engine)
    {
        _engine = engine;
        _unicorn = engine.Engine;
    }

    [MemberNotNull(nameof(_clientInfo))]
    private void CheckInitialized()
    {
        if (_clientInfo == null)
            throw new InvalidOperationException("The debug provider has not been initialized.");
    }

    public int LineToClient(int local)
        => _clientInfo!.LinesStartAt1 ? local + 1 : local;

    public int LineFromClient(int client)
        => _clientInfo!.LinesStartAt1 ? client - 1 : client;

    public int ColumnToClient(int local)
        => _clientInfo!.ColumnsStartAt1 ? local + 1 : local;

    public int ColumnFromClient(int client)
        => _clientInfo!.ColumnsStartAt1 ? client - 1 : client;

    public InitializeResponse Initialize(InitializeRequestArguments clientData)
    {
        _clientInfo = clientData;

        return new InitializeResponse()
        {
            SupportsCancelRequest = false,
            SupportedChecksumAlgorithms = new Container<ChecksumAlgorithm>(ChecksumAlgorithm.Md5,
                ChecksumAlgorithm.Sha1, ChecksumAlgorithm.Sha256, ChecksumAlgorithm.Timestamp),
            SupportsClipboardContext = false,
            SupportsCompletionsRequest = false,
            SupportsConditionalBreakpoints = false,
            SupportsDataBreakpoints = true,
            SupportsDisassembleRequest = false, // TODO
            SupportsExceptionOptions = false,
            SupportsFunctionBreakpoints = false,    // TODO
            SupportsInstructionBreakpoints = false, // TODO,
            SupportsLogPoints = true,
            SupportsModulesRequest = true,
            SupportsRestartFrame = false,
            SupportsRestartRequest = true,
            SupportsSetExpression = false, // TODO?
            SupportsSetVariable = true,
            SupportsStepBack = true,
            SupportsSteppingGranularity = false,
            SupportsTerminateRequest = true,
            SupportSuspendDebuggee = false,
            SupportTerminateDebuggee = false,
            SupportsBreakpointLocationsRequest = true,
            SupportsConfigurationDoneRequest = false,
            SupportsEvaluateForHovers = false, //TODO?
            SupportsExceptionFilterOptions = false,
            SupportsExceptionInfoRequest = true,
            SupportsGotoTargetsRequest = true,
            SupportsHitConditionalBreakpoints = false, // TODO
            SupportsLoadedSourcesRequest = true,
            SupportsReadMemoryRequest = true,
            SupportsTerminateThreadsRequest = false,
            SupportsValueFormattingOptions = true,
            SupportsWriteMemoryRequest = true,
            SupportsDelayedStackTraceLoading = false,
            SupportsStepInTargetsRequest = false,
            ExceptionBreakpointFilters = this.MakeFilters()
        };
    }

    private Container<ExceptionBreakpointsFilter> MakeFilters()
    {
        // TODO
        return new[]
        {
            new ExceptionBreakpointsFilter()
                { Label = "All Unicorn exceptions", Filter = "all", SupportsCondition = false }
        };
    }

    public IEnumerable<GotoTarget> GetGotoTargets(Source source, long line, long? column) =>
        throw new NotImplementedException();

    public SetVariableResponse SetVariable(long containerId, string variableName, string value, ValueFormat? format) =>
        throw new NotImplementedException();

    public SourceResponse GetSource(long sourceReference) => throw new NotImplementedException();

    public SourceResponse GetSource(Source source) => throw new NotImplementedException();
    
    public DataBreakpointInfoResponse GetDataBreakpointInfo(long containerId, string variableName) => throw new NotImplementedException();

    public DataBreakpointInfoResponse GetDataBreakpointInfo(string expression) => throw new NotImplementedException();
    
    public EvaluateResponse EvaluateExpression(string expression, EvaluateArgumentsContext? context,
        ValueFormat? format) => throw new NotImplementedException();

    public ExceptionInfoResponse GetLastExceptionInfo() => throw new NotImplementedException();

    public StackTraceResponse MakeStackTrace() => throw new NotImplementedException();

    public ScopesResponse MakeVariableScopes() => throw new NotImplementedException();

    public IEnumerable<BreakpointLocation> GetBreakpointLocations(Source source, int line, int? endLine) =>
        throw new NotImplementedException();

    public IEnumerable<ExceptionBreakpointsFilter> GetExceptionBreakpointFilters() =>
        throw new NotImplementedException();

    public IEnumerable<DisassembledInstruction> Disassemble(string memoryReference, long? byteOffset,
        long? instructionOffset, long instructionCount,
        bool resolveSymbols) =>
        throw new NotImplementedException();
}
