// DebugProvider.cs
// Author: Ondřej Ondryáš

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Extensions;
using Code4Arm.Unicorn.Constants;
using MediatR;
using Newtonsoft.Json.Linq;
using ExecutionEngineException = Code4Arm.ExecutionCore.Execution.Exceptions.ExecutionEngineException;

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
            SupportsDataBreakpoints = false,    // TODO
            SupportsDisassembleRequest = false, // TODO
            SupportsExceptionOptions = false,
            SupportsFunctionBreakpoints = false,    // TODO
            SupportsInstructionBreakpoints = false, // TODO
            SupportsLogPoints = true,
            SupportsModulesRequest = false, // TODO?
            SupportsRestartFrame = false,
            SupportsRestartRequest = true,
            SupportsSetExpression = false, // TODO?
            SupportsSetVariable = true,
            SupportsStepBack = false, // TODO
            SupportsSteppingGranularity = false,
            SupportsTerminateRequest = true,
            SupportSuspendDebuggee = false,
            SupportTerminateDebuggee = false,
            SupportsBreakpointLocationsRequest = false, // TODO
            SupportsConfigurationDoneRequest = true,
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
                {Label = "All Unicorn exceptions", Filter = "all", SupportsCondition = false}
        };
    }

    public IEnumerable<GotoTarget> GetGotoTargets(Source source, long line, long? column)
    {
        throw new NotImplementedException();
    }

    /// <summary>
    /// 
    /// </summary>
    /// <param name="containerId">The Variables reference number.</param>
    /// <param name="variableName"></param>
    /// <param name="value"></param>
    /// <param name="format"></param>
    /// <returns></returns>
    public SetVariableResponse SetVariable(long containerId, string variableName, string value, ValueFormat? format)
    {
        // TODO
        if (containerId == 1)
        {
            var regId = int.Parse(variableName[1..]);
            var isHex = format?.Hex ?? false;

            if (!int.TryParse(value, isHex ? NumberStyles.HexNumber : NumberStyles.Integer,
                    NumberFormatInfo.InvariantInfo, out var val))
                throw new InvalidValueException();

            _engine.Engine.RegWrite(Arm.Register.GetRegister(regId), val);

            return new SetVariableResponse()
            {
                Value = val.ToString(isHex ? "x" : ""),
                Type = "General-purpose register"
            };
        }

        throw new InvalidVariableReferenceException();
    }

    public DataBreakpointInfoResponse GetDataBreakpointInfo(long containerId, string variableName) =>
        throw new NotImplementedException();

    public DataBreakpointInfoResponse GetDataBreakpointInfo(string expression) => throw new NotImplementedException();

    public ExceptionInfoResponse GetLastExceptionInfo() => throw new NotImplementedException();

    private Regex _exprRegex =
        new(
            @"(?:\((?<type>[\w ]*?)\))?\s*\[\s*R(?<base>[0-9]{1,2})(?:\s*,\s*(?:(?<regofSign>[+-])?R(?<regoof>[0-9]{1,2})(?:\s*,\s*(?<shift>LSL|LSR|ASR|ROR)\s+(?<shImm>\d+))?|(?:(?<immofSign>[+-])?(?<immof>\d+))))?\s*\]",
            RegexOptions.Compiled);

    public EvaluateResponse EvaluateExpression(string expression, EvaluateArgumentsContext? context,
        ValueFormat? format)
    {
        // Expression variants:
        // [Rx]
        // [Rx, +-Ry]
        // [Rx, +-Ry, shift imm]
        // [Rx, +-imm]
        // prefixes: (float) (double) (byte) (short) (int) (long) & unsig. variants

        var match = _exprRegex.Match(expression);

        if (!match.Success)
            throw new InvalidExpressionException();

        // TODO

        var regStr = match.Groups["base"].Value;

        if (!int.TryParse(regStr, out var reg) || reg < 0 || reg > 15)
            throw new InvalidExpressionException();

        var address = _engine.Engine.RegRead<uint>(Arm.Register.GetRegister(reg));
        var isUint = match.Groups["type"].Value == "uint";
        string ret;

        if (isUint)
        {
            var val = _engine.Engine.MemReadDirect<uint>(address);
            ret = val.ToString();
        }
        else
        {
            var val = _engine.Engine.MemReadDirect<int>(address);
            ret = val.ToString();
        }

        return new EvaluateResponse() {Result = ret};
    }


    public async Task<StackTraceResponse> MakeStackTrace()
    {
        if (_engine.ExecutableInfo == null)
            throw new InvalidOperationException(); // TODO

        var frames = new StackFrame[1];

        var sourceIndex = _engine.CurrentStopSourceIndex;
        var source = _engine.State == ExecutionState.PausedBreakpoint ? _engine.CurrentBreakpoint?.Source : null;

        if (source is null && _engine.ExecutableInfo.Sources.Count > sourceIndex)
        {
            var exeSource = _engine.ExecutableInfo.Sources[sourceIndex];
            source = await this.GetSource(sourceIndex, exeSource);
        }

        frames[0] = new StackFrame()
        {
            Id = 1,
            Line = this.LineToClient(_engine.CurrentStopLine),
            CanRestart = false,
            PresentationHint = StackFramePresentationHint.Normal,
            Source = source,
            Name = "Current execution state",
            InstructionPointerReference = _engine.CurrentPc.ToString()
        };

        var ret = new StackTraceResponse() {StackFrames = new Container<StackFrame>(frames), TotalFrames = 1};

        return ret;
    }

    public ScopesResponse MakeVariableScopes()
    {
        return new ScopesResponse()
        {
            Scopes = new Container<Scope>(new Scope()
            {
                Name = "Registers",
                NamedVariables = 15,
                VariablesReference = 1,
                PresentationHint = "registers"
            }, new Scope()
            {
                Name = "Data",
                NamedVariables = 2,
                VariablesReference = 2,
                PresentationHint = "locals"
            })
        };
    }

    public IEnumerable<BreakpointLocation> GetBreakpointLocations(Source source, int line, int? endLine) =>
        throw new NotImplementedException();

    public IEnumerable<ExceptionBreakpointsFilter> GetExceptionBreakpointFilters() =>
        throw new NotImplementedException();

    public IEnumerable<Variable> GetChildVariables(long containerId, string parentVariableName, long? start,
        long? count, ValueFormat? format) =>
        Enumerable.Empty<Variable>(); // TODO

    public IEnumerable<Variable> GetChildVariables(long variablesReference, long? start, long? count,
        ValueFormat? format)
    {
        if (variablesReference == 1)
        {
            var toRet = count.HasValue ? Math.Min(count.Value, 16) : 16;
            for (var i = 0; i < toRet; i++)
            {
                yield return new Variable()
                {
                    Name = "R" + i,
                    Type = "General-purpose register",
                    Value = (_engine.Engine.RegRead<int>(Arm.Register.GetRegister(i)))
                        .ToString((format?.Hex ?? false) ? "x" : "")
                };
            }
        }

        if (variablesReference == 2)
        {
            yield return new Variable()
            {
                Name = "Test 1",
                Type = "Memory",
                Value = (456121).ToString((format?.Hex ?? false) ? "x" : "")
            };

            yield return new Variable()
            {
                Name = "Test 2",
                Type = "Memory",
                Value = (787878).ToString((format?.Hex ?? false) ? "x" : "")
            };
        }
    }

    public IEnumerable<DisassembledInstruction> Disassemble(string memoryReference, long? byteOffset,
        long? instructionOffset, long instructionCount,
        bool resolveSymbols) =>
        throw new NotImplementedException();

    #region Memory

    public ReadMemoryResponse ReadMemory(string memoryReference, long count, long? offset) =>
        throw new NotImplementedException();

    public WriteMemoryResponse
        WriteMemory(string memoryReference, bool allowPartial, long? offset, string dataEncoded) =>
        throw new NotImplementedException();

    #endregion

    #region Sources

    public async Task<SourceResponse> GetSourceContents(long sourceReference)
    {
        sourceReference -= 1; // Source references are indices in the executable sources array offset by +1

        var exeSources = _engine.ExecutableInfo?.Sources;

        if (exeSources is null)
            throw new ExecutableNotLoadedException(_engine.ExecutionId, nameof(GetSourceContents));

        if (exeSources.Count <= sourceReference)
            throw new InvalidSourceException(_engine.ExecutionId, nameof(GetSourceContents));

        var exeSource = exeSources[(int) sourceReference];
        using var locatedFile = await exeSource.SourceFile.LocateAsync();
        var contents = await File.ReadAllTextAsync(locatedFile.FileSystemPath);

        return new SourceResponse() {Content = contents};
    }

    private int GetSourceReference(Source? source, [CallerMemberName] string caller = "")
    {
        if (source?.SourceReference is > 0)
            return (int) source.SourceReference.Value;

        if (source?.AdapterData != null)
        {
            try
            {
                return source.AdapterData.Value<int>();
            }
            catch (InvalidCastException)
            {
                // Intentionally left blank
            }
        }

        if (source?.Path == null)
            throw new InvalidSourceException(_engine.ExecutionId, caller);

        var i = 1;
        foreach (var exeSource in _engine.ExecutableInfo!.Sources)
        {
            if (exeSource.ClientPath == null || source.Path == null)
                continue;

            // TODO: Handle path case sensitivity?
            if (exeSource.ClientPath.Equals(source.Path, StringComparison.OrdinalIgnoreCase))
                return i;

            i++;
        }

        throw new InvalidSourceException(_engine.ExecutionId, caller);
    }

    public async Task<SourceResponse> GetSourceContents(Source source)
    {
        var reference = this.GetSourceReference(source);

        return await this.GetSourceContents(reference);
    }

    private async Task<Source> GetSource(int sourceIndex, ExecutableSource exeSource)
    {
        var isClientSide = exeSource.ClientPath != null;

        return new Source()
        {
            Name = exeSource.SourceFile.Name,
            Path = exeSource.ClientPath ?? exeSource.SourceFile.Name,
            Origin = isClientSide ? null : "execution service",
            //PresentationHint = isClientSide ? null : SourcePresentationHint.Deemphasize,
            SourceReference = isClientSide ? null : (sourceIndex + 1),
            Checksums = await MakeChecksums(exeSource),
            AdapterData = new JValue(sourceIndex + 1)
        };
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
            ret[i] = await this.GetSource(i, exeSource);
            i++;
        }

        return ret;
    }

    public string? GetCompilationPathForSource(Source source)
    {
        if (_engine.ExecutableInfo is null)
            throw new ExecutableNotLoadedException(_engine.ExecutionId, nameof(GetSourceContents));

        if (_engine.ExecutableInfo is not Executable exe)
            return null;

        var exeSources = exe.Sources;

        // Source references are indices in the executable sources array offset by +1
        var reference = this.GetSourceReference(source) - 1;

        return exeSources.Count <= reference ? null : exeSources[reference].BuildPath;
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
