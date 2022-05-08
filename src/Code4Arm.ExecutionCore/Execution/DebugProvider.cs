// DebugProvider.cs
// Author: Ondřej Ondryáš

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.Unicorn.Abstractions;
using MediatR;
using Newtonsoft.Json.Linq;

namespace Code4Arm.ExecutionCore.Execution;

internal class DebugProvider : IDebugProvider, IDebugProtocolSourceLocator
{
    private readonly ExecutionEngine _engine;
    private readonly IUnicorn _unicorn;
    private InitializeRequestArguments? _clientInfo;

    public DebugProvider(ExecutionEngine engine, IMediator mediator)
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

    private InitializeResponse MakeCapabilities()
    {
        return new InitializeResponse()
        {
            SupportsCancelRequest = false,
            SupportedChecksumAlgorithms =
                new Container<ChecksumAlgorithm>(ChecksumAlgorithm.Md5, ChecksumAlgorithm.Timestamp),
            SupportsClipboardContext = false,
            SupportsCompletionsRequest = false,
            SupportsConditionalBreakpoints = false,
            SupportsDataBreakpoints = true,
            SupportsDisassembleRequest = false, // TODO
            SupportsExceptionOptions = false,
            SupportsFunctionBreakpoints = false,    // TODO
            SupportsInstructionBreakpoints = false, // TODO,
            SupportsLogPoints = true,
            SupportsModulesRequest = false, // TODO?
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

    public InitializeResponse Initialize(InitializeRequestArguments clientData)
    {
        _clientInfo = clientData;

        var capabilities = this.MakeCapabilities();

        return capabilities;
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

    public IEnumerable<GotoTarget> GetGotoTargets(Source source, long line, long? column)
    {
        throw new NotImplementedException();
    }

    public SetVariableResponse SetVariable(long containerId, string variableName, string value, ValueFormat? format) =>
        throw new NotImplementedException();

    public DataBreakpointInfoResponse GetDataBreakpointInfo(long containerId, string variableName) =>
        throw new NotImplementedException();

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

    public ReadMemoryResponse ReadMemory(string memoryReference, long count, long? offset) =>
        throw new NotImplementedException();

    public WriteMemoryResponse
        WriteMemory(string memoryReference, bool allowPartial, long? offset, string dataEncoded) =>
        throw new NotImplementedException();

    public IEnumerable<Variable> GetChildVariables(long containerId, string parentVariableName, long? start,
        long? count,
        ValueFormat? format) =>
        throw new NotImplementedException();

    public IEnumerable<Variable> GetChildVariables(long variablesReference, long? start, long? count,
        ValueFormat? format) => throw new NotImplementedException();

    public IEnumerable<DisassembledInstruction> Disassemble(string memoryReference, long? byteOffset,
        long? instructionOffset, long instructionCount,
        bool resolveSymbols) =>
        throw new NotImplementedException();

    #region Sources

    public async Task<SourceResponse> GetSourceContents(long sourceReference)
    {
        sourceReference -= 1; // Source references are indices in the executable sources array offset by +1

        var exeSources = _engine.ExecutableInfo?.Sources;

        if (exeSources is null)
            throw new ExecutableNotLoadedException(_engine.ExecutionId, nameof(GetSourceContents));

        if (exeSources.Count <= sourceReference)
            throw new InvalidSourceException(_engine.ExecutionId, nameof(GetSourceContents));

        var exeSource = exeSources[(int)sourceReference];
        using var locatedFile = await exeSource.SourceFile.LocateAsync();
        var contents = await File.ReadAllTextAsync(locatedFile.FileSystemPath);

        return new SourceResponse() { Content = contents };
    }

    private int GetSourceReference(Source? source)
    {
        if (source?.SourceReference is > 0)
            return (int)source.SourceReference.Value;

        if (source?.AdapterData == null)
            throw new InvalidSourceException(_engine.ExecutionId, nameof(GetSourceContents));

        try
        {
            return source.AdapterData.Value<int>();
        }
        catch (InvalidCastException)
        {
            throw new InvalidSourceException(_engine.ExecutionId, nameof(GetSourceContents));
        }
    }

    public async Task<SourceResponse> GetSourceContents(Source source)
    {
        var reference = this.GetSourceReference(source);

        return await this.GetSourceContents(reference);
    }

    public async Task<IEnumerable<Source>> GetSources()
    {
        var exeSources = _engine.ExecutableInfo?.Sources;

        if (exeSources is null)
            return Enumerable.Empty<Source>();

        var ret = new Source[exeSources.Count];
        var i = 0;

        foreach (var exeSource in exeSources)
        {
            var isClientSide = exeSource.ClientPath != null;

            ret[i] = new Source()
            {
                Name = exeSource.SourceFile.Name,
                Path = exeSource.ClientPath ?? exeSource.SourceFile.Name,
                Origin = isClientSide ? null : "execution service",
                //PresentationHint = isClientSide ? null : SourcePresentationHint.Deemphasize,
                SourceReference = isClientSide ? null : (i + 1),
                Checksums = await MakeChecksums(exeSource),
                AdapterData = new JValue(i + 1)
            };

            i++;
        }

        return ret;
    }

    public string GetCompilationPathForSource(Source source)
    {
        var asmObj = this.GetObjectForSource(source);

        if (asmObj == null)
            throw new ArgumentException("Source not found.", nameof(source));

        return asmObj.ObjectFilePath;
    }

    public AssembledObject? GetObjectForSource(Source source)
    {
        if (_engine.ExecutableInfo is null)
            throw new ExecutableNotLoadedException(_engine.ExecutionId, nameof(GetSourceContents));

        if (_engine.ExecutableInfo is not Executable exe)
            return null;

        var exeSourceObjects = exe.SourceObjects;

        // Source references are indices in the executable sources array offset by +1
        var reference = this.GetSourceReference(source) - 1;

        return exeSourceObjects.Count <= reference ? null : exeSourceObjects[reference];
    }

    private static async Task<Checksum[]> MakeChecksums(ExecutableSource exeSource)
    {
        // TODO: Cache for InitFile

        using var locatedFile = await exeSource.SourceFile.LocateAsync();
        await using var file = File.OpenRead(locatedFile.FileSystemPath);
        using var md5 = MD5.Create();
        var hash = await md5.ComputeHashAsync(file);
        var ret = new Checksum[2];

        ret[0] = new Checksum()
        {
            Algorithm = ChecksumAlgorithm.Md5,
            Value = BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant()
        };

        ret[1] = new Checksum()
        {
            Algorithm = ChecksumAlgorithm.Timestamp,
            Value = locatedFile.Version.ToString()
        };

        return ret;
    }

    #endregion
}
