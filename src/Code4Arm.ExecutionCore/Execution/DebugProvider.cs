// DebugProvider.cs
// Author: Ondřej Ondryáš

using System.Buffers;
using System.Buffers.Text;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Debugger;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionCore.Protocol.Events;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.Unicorn;
using Code4Arm.Unicorn.Constants;
using ELFSharp.ELF.Sections;
using Gee.External.Capstone.Arm;
using Newtonsoft.Json.Linq;
using StepBackMode = Code4Arm.ExecutionCore.Execution.Configuration.StepBackMode;

namespace Code4Arm.ExecutionCore.Execution;

/// <summary>
/// The <see cref="DebugProvider"/> class provides most of the debugging functionality that is not directly related
/// to the execution process. This includes mainly handling requests that provide information about the executable
/// (Sources, Goto targets, Breakpoint locations etc.) or that provide debugging features (Variables, Expressions etc.).
/// </summary>
internal partial class DebugProvider : IDebugProvider, IDebugProtocolSourceLocator, IFormattedTraceObserver
{
    private readonly ExecutionEngine _engine;
    private InitializeRequestArguments? _clientInfo;
    private CultureInfo _clientCulture;

    private readonly Dictionary<long, IVariable> _variables = new();
    private readonly Dictionary<string, IVariable> _topLevel = new();

    private readonly Dictionary<long, ITraceable> _steppedTraceables = new();
    private readonly Dictionary<long, ITraceable> _hookTraceables = new();
    private long _nextTraceableId = long.MinValue;

    private Executable Executable => (_engine.ExecutableInfo as Executable) ?? throw new ExecutableNotLoadedException();
    public InitializeRequestArguments? ClientInfo => _clientInfo;

    public DebugProvider(ExecutionEngine engine, DebuggerOptions options)
    {
        _engine = engine;
        Options = options;
        _clientCulture = CultureInfo.InvariantCulture;
    }

    public DebuggerOptions Options { get; set; }

    [MemberNotNull(nameof(_clientInfo), nameof(_clientCulture))]
    private void CheckInitialized()
    {
        if (_clientInfo == null || _clientCulture == null)
            throw new NotInitializedException();
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
            SupportsDisassembleRequest = true,
            SupportsExceptionOptions = false,
            SupportsFunctionBreakpoints = false,
            SupportsInstructionBreakpoints = true,
            SupportsLogPoints = true,
            SupportsModulesRequest = false, // TODO?
            SupportsRestartFrame = false,
            SupportsRestartRequest = true,
            SupportsSetExpression = true,
            SupportsSetVariable = true,
            SupportsStepBack = _engine.Options.StepBackMode != StepBackMode.None,
            SupportsSteppingGranularity = false,
            SupportsTerminateRequest = true,
            SupportSuspendDebuggee = false,
            SupportTerminateDebuggee = false,
            SupportsBreakpointLocationsRequest = true,
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

        if (!string.IsNullOrEmpty(clientData.Locale))
        {
            try
            {
                _clientCulture = CultureInfo.GetCultureInfo(clientData.Locale);
            }
            catch (CultureNotFoundException)
            {
                _clientCulture = CultureInfo.InvariantCulture;
            }
        }

        var capabilities = this.MakeCapabilities();

        return capabilities;
    }

    private Container<ExceptionBreakpointsFilter> MakeFilters()
    {
        // Intentionally blank: break on all exceptions (what is there left to do)
        return new Container<ExceptionBreakpointsFilter>();
    }

    public async Task<IEnumerable<DisassembledInstruction>> Disassemble(string memoryReference, long? byteOffset,
        long? instructionOffset, long instructionCount,
        bool resolveSymbols)
    {
        if (!FormattingUtils.TryParseAddress(memoryReference, out var address))
            throw new Exception(); // TODO

        if (byteOffset.HasValue)
            address += (uint)byteOffset.Value;

        if (instructionOffset.HasValue)
            address += (uint)(instructionOffset.Value * 4);

        // Align address to 4 bytes
        address = ((address + 3) / 4) * 4;
        var bytesCount = (int)(instructionCount * 4);

        var (startAddress, endAddress) = this.DetermineMappedMemoryRegion(address, bytesCount);
        if (startAddress == 0 && endAddress == 0)
        {
            return Enumerable.Range(0, (int)instructionCount).Select(i => new DisassembledInstruction()
            {
                Address = FormattingUtils.FormatAddress((uint)(address + i * 4)),
                Instruction = "INVALID MEMORY ADDRESS",
                InstructionBytes = "00 00 00 00"
            });
        }

        var actualCount = (int)(endAddress - startAddress);
        var bytesOffset = (int)(startAddress - address);

        byte[]? rentedBytes = null;

        try
        {
            byte[] bytes;
            if (actualCount < ExecutionEngine.MaxArrayPoolSize)
            {
                bytes = _engine.ArrayPool.Rent(actualCount);
                rentedBytes = bytes;
            }
            else
            {
                bytes = new byte[actualCount];
            }

            _engine.Engine.MemRead(startAddress, bytes, (nuint)actualCount);

            var cap = new CapstoneArmDisassembler(ArmDisassembleMode.Arm | ArmDisassembleMode.V8)
                { EnableInstructionDetails = true, EnableSkipDataMode = true };
            var disAsm = cap.Disassemble(bytes, startAddress, actualCount / 4);

            var ret = new List<DisassembledInstruction>((int)instructionCount);
            var ix = 0;

            for (var i = 0; i < instructionCount; i++)
            {
                var instrOffset = i * 4;
                var instrAddress = address + instrOffset;
                if (instrAddress < startAddress || instrAddress >= endAddress)
                {
                    ret.Add(new DisassembledInstruction()
                    {
                        Address = FormattingUtils.FormatAddress((uint)instrAddress),
                        Instruction = "INVALID MEMORY ADDRESS",
                        InstructionBytes = "00 00 00 00"
                    });

                    continue;
                }

                var (line, sourceIndex) = this.GetAddressInfo((uint)instrAddress);
                var source = sourceIndex == -1 ? null : await this.GetSource(sourceIndex);
                var instrBytes = bytes[(instrOffset - bytesOffset)..(instrOffset - bytesOffset + 4)];
                var dis = disAsm[ix++];

                ret.Add(new DisassembledInstruction()
                {
                    Address = FormattingUtils.FormatAddress((uint)instrAddress),
                    Instruction = $"{dis.Mnemonic} {dis.Operand}",
                    Line = line == -1 ? null : this.LineToClient(line),
                    Location = source,
                    InstructionBytes = $"{instrBytes[3]:X2} {instrBytes[2]:X2} {instrBytes[1]:X2} {instrBytes[0]:X2}"
                });
            }

            return ret;
        }
        catch (UnicornException e)
        {
            throw new InvalidMemoryOperationException(ExceptionMessages.InvalidMemoryRead, e);
        }
        finally
        {
            if (rentedBytes != null)
                _engine.ArrayPool.Return(rentedBytes);
        }
    }

    public (int Line, int SourceIndex) GetAddressInfo(uint address)
    {
        var lineInfo = _engine.LineResolver!.GetSourceLine(address, out var displacement);

        if (lineInfo == default)
            return (-1, -1);

        if (displacement != 0)
        {
            return (-1, _engine.DetermineSourceIndexForAddress(address));
        }
        else
        {
            var line = (int)lineInfo.Line - 1; // in DWARF, the lines are numbered from 1
            var i = 0;
            foreach (var exeSource in _engine.ExecutableInfo!.Sources)
            {
                if (exeSource.BuildPath.Equals(lineInfo.File.Path, StringComparison.OrdinalIgnoreCase))
                    break;

                i++;
            }

            var sourceIndex = (i == _engine.ExecutableInfo!.Sources.Count ? -1 : i);

            return (line, sourceIndex);
        }
    }

    public IEnumerable<GotoTarget> GetGotoTargets(Source source, int line, int? column)
    {
        this.CheckInitialized();

        line = this.LineFromClient(line);

        var sourcePath = this.GetCompilationPathForSource(source);

        if (sourcePath == null)
            return Enumerable.Empty<GotoTarget>();

        var address = _engine.LineResolver!.GetAddress(sourcePath, line + 1);

        if (address == uint.MaxValue)
            return Enumerable.Empty<GotoTarget>();

        return Enumerable.Repeat(new GotoTarget()
        {
            Id = address,
            Line = this.LineToClient(line),
            Label = "Here",
            InstructionPointerReference = FormattingUtils.FormatAddress(address)
        }, 1);
    }

    public ExceptionInfoResponse GetLastExceptionInfo()
    {
        this.CheckInitialized();

        var id = _engine.LastStopCause switch
        {
            ExecutionEngine.StopCause.Normal => throw new NoExceptionDataException(),
            ExecutionEngine.StopCause.Interrupt => "interrupt",
            ExecutionEngine.StopCause.InvalidInstruction => "invalid instruction",
            ExecutionEngine.StopCause.InvalidMemoryAccess => "invalid memory access",
            ExecutionEngine.StopCause.TrampolineUnbound => "invalid emulated function",
            ExecutionEngine.StopCause.TimeoutOrExternalCancellation => "timeout",
            ExecutionEngine.StopCause.UnicornException => "runtime error",
            _ => throw new ArgumentOutOfRangeException()
        };

        var description = _engine.LastStopCause switch
        {
            ExecutionEngine.StopCause.Normal => throw new NoExceptionDataException(),
            ExecutionEngine.StopCause.Interrupt =>
                "The CPU has issued an interrupt.\n" +
                $"  Interrupt number: {_engine.LastStopData.InterruptNumber}.\n" +
                $"  R7 value: {_engine.LastStopData.InterruptR7:x}.",

            ExecutionEngine.StopCause.InvalidInstruction => "Invalid instruction/opcode.",
            ExecutionEngine.StopCause.InvalidMemoryAccess =>
                "Invalid memory access." +
                $"  Interrupt number: {_engine.LastStopData.InterruptNumber}.\n" +
                $"  R7 value: {_engine.LastStopData.InterruptR7:x}.",
            ExecutionEngine.StopCause.TrampolineUnbound =>
                "Invalid attempt to jump into the simulated functions memory segment.",
            ExecutionEngine.StopCause.TimeoutOrExternalCancellation =>
                "The emulation reached its maximum run time and timed out.",
            ExecutionEngine.StopCause.UnicornException => "Emulator error.",
            _ => throw new ArgumentOutOfRangeException()
        };

        return new ExceptionInfoResponse()
        {
            Description = description,
            ExceptionId = id,
            BreakMode = _engine.LastStopCause == ExecutionEngine.StopCause.Interrupt
                ? ExceptionBreakMode.Unhandled
                : ExceptionBreakMode.Always
        };
    }

    public async Task<StackTraceResponse> MakeStackTrace()
    {
        this.CheckInitialized();

        var frames = new StackFrame[1];

        var sourceIndex = _engine.CurrentStopSourceIndex;
        var source = _engine.State == ExecutionState.PausedBreakpoint ? _engine.CurrentBreakpoint?.Source : null;

        if (source is null && Executable.Sources.Count > sourceIndex && sourceIndex != -1)
        {
            var exeSource = Executable.Sources[sourceIndex];
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
            InstructionPointerReference = FormattingUtils.FormatAddress(_engine.CurrentPc)
        };

        var ret = new StackTraceResponse() { StackFrames = new Container<StackFrame>(frames), TotalFrames = 1 };

        return ret;
    }

    public IEnumerable<BreakpointLocation> GetBreakpointLocations(Source source, int line, int? endLine)
    {
        this.CheckInitialized();

        var sourceObject = this.GetObjectForSource(source);

        if (sourceObject is null or { IsProgramLine: null })
            return Enumerable.Empty<BreakpointLocation>();

        line = this.LineFromClient(line);
        var endLineVal = endLine.HasValue
            ? Math.Min(sourceObject.IsProgramLine.Length - 1, this.LineFromClient(endLine.Value))
            : sourceObject.IsProgramLine.Length - 1;

        if (line >= sourceObject.IsProgramLine.Length || line > endLineVal)
            return Enumerable.Empty<BreakpointLocation>();

        var ret = new List<BreakpointLocation>(endLineVal - line + 1);
        for (var i = line; i <= endLineVal; i++)
        {
            if (sourceObject.IsProgramLine[i])
                ret.Add(new BreakpointLocation()
                {
                    Line = this.LineToClient(i)
                });
        }

        return ret;
    }

    #region Data breakpoints

    public DataBreakpointInfoResponse GetDataBreakpointInfo(long parentVariablesReference, string variableName)
    {
        this.CheckInitialized();

        var targetVariable = this.GetVariable(parentVariablesReference, variableName);

        if (targetVariable is null)
            throw new InvalidVariableException();

        if (targetVariable is not ITraceable traceable)
            return new DataBreakpointInfoResponse() { Description = "This variable cannot be traced." };

        return new DataBreakpointInfoResponse()
        {
            DataId = $"{parentVariablesReference}.{variableName}",
            Description = this.GetVariableName(targetVariable),
            //AccessTypes = new Container<DataBreakpointAccessType>(DataBreakpointAccessType.Write, DataBreakpointAccessType.Read, DataBreakpointAccessType.ReadWrite), // TODO
            CanPersist = traceable.CanPersist
        };
    }

    public DataBreakpointInfoResponse GetDataBreakpointInfo(string expression) => throw new NotImplementedException();

    public void RefreshSteppedTraces()
    {
        if (_steppedTraceables.Count == 0)
            return;

        foreach (var traceable in _steppedTraceables.Values)
        {
            traceable.TraceStep(_engine);
        }
    }

    public void ClearDataBreakpoints()
    {
        foreach (var (_, traceable) in _steppedTraceables)
        {
            traceable.StopTrace(_engine, this);
        }

        foreach (var (_, traceable) in _hookTraceables)
        {
            traceable.StopTrace(_engine, this);
        }

        _steppedTraceables.Clear();
        _hookTraceables.Clear();
    }

    private string? _oldTraceVal, _newTraceVal;

    public void TraceTriggered(long traceId, string? oldValue, string? newValue)
    {
        _engine.LastStopCause = ExecutionEngine.StopCause.DataBreakpoint;
        _engine.LastStopData.DataBreakpointId = traceId;
        if (_hookTraceables.ContainsKey(traceId))
            _engine.LastStopData.MovePcAfterDataBreakpoint = true;

        _oldTraceVal = oldValue;
        _newTraceVal = newValue;

        _engine.Engine.EmuStop();
    }

    public void TraceTriggered(long traceId)
    {
        this.TraceTriggered(traceId, null, null);
    }

    public VariableContext GetTraceTriggerContext()
    {
        this.CheckInitialized();

        return new VariableContext(_engine, _clientCulture, Options, Options.VariableNumberFormat);
    }

    public async Task LogTraceInfo()
    {
        var traceId = _engine.LastStopData.DataBreakpointId;

        var varFound = _steppedTraceables.TryGetValue(traceId, out var traceable) ||
            _hookTraceables.TryGetValue(traceId, out traceable);

        if (!varFound || traceable is not IVariable variable)
        {
            await _engine.LogDebugConsole("Hit data breakpoint.");

            return;
        }

        var name = this.GetVariableName(variable);
        var hasValues = _oldTraceVal != null || _newTraceVal != null;

        await _engine.LogDebugConsole($"Hit data breakpoint: {name}", false, hasValues ? OutputEventGroup.Start : null);

        if (_oldTraceVal != null)
            await _engine.LogDebugConsole($"Old value: {_oldTraceVal}");
        if (_newTraceVal != null)
            await _engine.LogDebugConsole($"New value: {_newTraceVal}");
        if (hasValues)
            await _engine.LogDebugConsole(string.Empty, false, OutputEventGroup.End);
    }

    public Breakpoint SetDataBreakpoint(DataBreakpoint breakpoint)
    {
        var dataIdSepI = breakpoint.DataId.IndexOf('.');

        if (dataIdSepI is -1 or 0 || dataIdSepI == (breakpoint.DataId.Length - 1))
            return new Breakpoint() { Verified = false };

        if (!long.TryParse(breakpoint.DataId[..dataIdSepI], out var varRef))
            return new Breakpoint() { Verified = false };

        var varName = breakpoint.DataId[(dataIdSepI + 1)..];

        var variable = this.GetVariable(varRef, varName);

        if (variable is null && this.TryResolveTopVariable(varRef, varName))
            variable = this.GetVariable(varRef, varName);

        if (variable is not ITraceable traceable)
            return new Breakpoint() { Verified = false };

        if (traceable.NeedsExplicitEvaluationAfterStep)
            _steppedTraceables.Add(_nextTraceableId, traceable);
        else
            _hookTraceables.Add(_nextTraceableId, traceable);

        traceable.InitTrace(_engine, this, _nextTraceableId);

        return new Breakpoint() { Id = _nextTraceableId++, Verified = true };
    }

    #endregion

    #region Variables

    private IVariable? GetVariable(long parentVariablesReference, string variableName)
    {
        IVariable targetVariable;

        if (ReferenceUtils.IsTopLevelContainer(parentVariablesReference))
        {
            if (!_topLevel.TryGetValue(variableName, out targetVariable!))
                return null;
        }
        else
        {
            if (!_variables.TryGetValue(parentVariablesReference, out var parentVariable))
                return null;

            if (!(parentVariable.Children?.TryGetValue(variableName, out targetVariable!) ?? false))
                return null;
        }

        return targetVariable;
    }

    /// <summary>
    /// Sets a variable, identified by its parent's Variables Reference number and its name.
    /// </summary>
    public async Task<SetVariableResponse> SetVariable(long parentVariablesReference, string variableName, string value,
        ValueFormat? format)
    {
        this.CheckInitialized();

        var targetVariable = this.GetVariable(parentVariablesReference, variableName);

        if (targetVariable == null)
            throw new InvalidVariableException();

        var ctx = new VariableContext(_engine, _clientCulture, Options, format);
        targetVariable.Set(value, ctx);

        targetVariable.Evaluate(ctx);

        if (targetVariable.IsViewOfParent)
        {
            await _engine.SendEvent(new InvalidatedEvent()
            {
                Areas = new Container<InvalidatedAreas>(InvalidatedAreas.Variables)
            });
        }

        return new SetVariableResponse()
        {
            Value = targetVariable.Get(ctx),
            Type = targetVariable.Type,
            NamedVariables = targetVariable.Children?.Count,
            VariablesReference = targetVariable.Reference
        };
    }

    /// <summary>
    /// Creates top-level variable scopes for general-purpose registers, CPU state registers, SIMD/FP registers,
    /// stack variables and data symbol variables. The enabled ones 
    /// </summary>
    public ScopesResponse MakeVariableScopes()
    {
        this.CheckInitialized();

        var ret = new List<Scope>(5);

        if (Options.EnableRegistersVariables)
        {
            ret.Add(new Scope()
            {
                Name = "Registers",
                NamedVariables = 14,
                VariablesReference = ReferenceUtils.MakeReference(ContainerType.Registers),
                PresentationHint = "registers"
            });
        }

        if (Options.EnableControlVariables)
        {
            // Basic: PC, APSR
            // Extended: + CPSR, FPEXC, FPSCR; MVFRx are not returned by unicorn
            var count = Options.EnableExtendedControlVariables ? 3 : 2;

            ret.Add(new Scope()
            {
                Name = "CPU state",
                NamedVariables = count,
                VariablesReference = ReferenceUtils.MakeReference(ContainerType.ControlRegisters),
                PresentationHint = "registers"
            });
        }

        if (Options.EnableSimdVariables)
        {
            ret.Add(new Scope()
            {
                Name = "SIMD/FP registers",
                NamedVariables = Options.TopSimdRegistersLevel == SimdRegisterLevel.D64 ? 32 : 16,
                VariablesReference = ReferenceUtils.MakeReference(ContainerType.SimdRegisters),
                PresentationHint = "registers"
            });
        }

        if (Options.EnableStackVariables)
        {
            var currentSize = this.GetStackSize();
            if (currentSize != 0)
            {
                ret.Add(new Scope()
                {
                    Name = "Stack",
                    IndexedVariables = currentSize / 4,
                    VariablesReference = ReferenceUtils.MakeReference(ContainerType.Stack),
                    PresentationHint = "locals"
                });
            }
        }

        if (Options.EnableAutomaticDataVariables)
        {
            ret.Add(new Scope()
            {
                Name = "Symbols",
                VariablesReference = ReferenceUtils.MakeReference(ContainerType.Symbols),
                PresentationHint = "locals"
            });
        }

        return new ScopesResponse()
        {
            Scopes = new Container<Scope>(ret)
        };
    }

    /// <summary>
    /// Returns children variables for a given Variables Reference.
    /// </summary>
    /// <param name="parentVariablesReference"></param>
    /// <param name="start"></param>
    /// <param name="count"></param>
    /// <param name="format"></param>
    /// <returns></returns>
    /// <exception cref="InvalidVariableException"></exception>
    public IEnumerable<Variable> GetChildVariables(long parentVariablesReference, int? start, int? count,
        ValueFormat? format)
    {
        this.CheckInitialized();

        if (_variables.TryGetValue(parentVariablesReference, out var variable) && variable.Children != null)
        {
            var ctx = new VariableContext(_engine, _clientCulture, Options, format);

            var targetVariables = variable.Children.Values;
            if (start.HasValue)
                targetVariables = targetVariables.Skip(start.Value);
            if (count.HasValue)
                targetVariables = targetVariables.Take(count.Value);

            var retArray = new Variable[(count ?? variable.Children.Count) - (start ?? 0)];
            var evaluated = false;

            if (variable.IsViewOfParent)
            {
                variable.Evaluate(ctx);
                evaluated = true;
            }

            var i = 0;
            foreach (var childVariable in targetVariables)
            {
                if (childVariable.IsViewOfParent && !evaluated)
                {
                    variable.Evaluate(ctx);
                    evaluated = true;
                }

                retArray[i++] = childVariable.GetAsProtocol(ctx, !childVariable.IsViewOfParent);
            }

            return retArray;
        }

        var containerType = ReferenceUtils.GetContainerType(parentVariablesReference);

        switch (containerType)
        {
            case ContainerType.Registers:
                return this.MakeRegistersVariables(format, start ?? 0, count ?? 15);
            case ContainerType.ControlRegisters:
                return this.MakeControlRegistersVariables(format);
            case ContainerType.SimdRegisters:
                return this.MakeSimdRegistersVariables(format, start ?? 0, count ?? 16);
            case ContainerType.Symbols:
                return this.MakeSymbolsVariables(format);
            case ContainerType.Stack:
                return this.MakeStackVariables(format);
            case ContainerType.SimdRegisterSubtypes:
            case ContainerType.SimdRegisterSubtypesValues:
            case ContainerType.StackSubtypes:
            case ContainerType.StackSubtypesValues:
            case ContainerType.ControlFlags:
            case ContainerType.RegisterSubtypes:
            case ContainerType.RegisterSubtypesValues:
            case ContainerType.ExpressionExtras:
            default:
                throw new InvalidVariableException();
        }
    }

    /// <summary>
    /// Creates Variables for CPU control/status registers. If 
    /// <see cref="DebuggerOptions.EnableExtendedControlVariables"/> is set to true, more registers are returned.
    /// </summary>
    private IEnumerable<Variable> MakeControlRegistersVariables(ValueFormat? format)
    {
        var ctx = new VariableContext(_engine, _clientCulture, Options, format);
        var retArray = new Variable[Options.EnableExtendedControlVariables ? 5 : 2];
        var i = 0;

        retArray[i++] = this.GetOrAddVariable(
            ReferenceUtils.MakeReference(ContainerType.ControlFlags, Arm.Register.APSR),
            () => new ControlRegisterVariable(Arm.Register.APSR, "APSR", "Application Processor State Register",
                new ControlRegisterFlag(31, "N", "Negative"),
                new ControlRegisterFlag(30, "Z", "Zero"),
                new ControlRegisterFlag(29, "C", "Carry"),
                new ControlRegisterFlag(28, "V", "Overflow"),
                new ControlRegisterFlag(27, "Q", "Cumulative saturation"),
                new ControlRegisterFlag(16, 4, "GE", "Greater than or Equal")
            ), true).GetAsProtocol(ctx, true);

        retArray[i++] = this.GetOrAddTopLevelVariable("PC",
                                () => new UnstructuredRegisterVariable(Arm.Register.PC, "PC", "Program Counter (R15)"))
                            .GetAsProtocol(ctx, true);

        if (Options.EnableExtendedControlVariables)
        {
            retArray[i++] = this.GetOrAddVariable(
                ReferenceUtils.MakeReference(ContainerType.ControlFlags, Arm.Register.CPSR),
                () => new ControlRegisterVariable(Arm.Register.CPSR, "CPSR", "Current Processor State Register",
                    new ControlRegisterFlag(31, "N", "Negative"),
                    new ControlRegisterFlag(30, "Z", "Zero"),
                    new ControlRegisterFlag(29, "C", "Carry"),
                    new ControlRegisterFlag(28, "V", "Overflow"),
                    new ControlRegisterFlag(27, "Q", "Cumulative saturation"),
                    new ControlRegisterFlag(23, "SSBS", "Speculative Store Bypass Safe"),
                    new ControlRegisterFlag(22, "PAN", "Privileged Access Never"),
                    new ControlRegisterFlag(21, "DIT", "Data Independent Timing"),
                    new ControlRegisterFlag(16, 4, "GE", "Greater than or Equal"),
                    new ControlRegisterFlag(9, "E", "Endianness state"),
                    new ControlRegisterFlag(8, "A", "SError interrupt mask"),
                    new ControlRegisterFlag(7, "I", "IRQ mask"),
                    new ControlRegisterFlag(6, "F", "FIQ mask"),
                    new ControlRegisterFlag(0, 4, "M", "Current PE mode",
                        "User", "FIQ", "IRQ", "Supervisor", "Monitor", "Abort", "Hypervisor", "Undefined", "System")
                ), true).GetAsProtocol(ctx, true);

            retArray[i++] = this.GetOrAddVariable(
                ReferenceUtils.MakeReference(ContainerType.ControlFlags, Arm.Register.FPEXC),
                () => new ControlRegisterVariable(Arm.Register.FPEXC, "FPEXC",
                    "FP Exception Control register",
                    new ControlRegisterFlag(31, "EX", "Exception"),
                    new ControlRegisterFlag(30, "EN", "Enable access to SIMD/FP"),
                    new ControlRegisterFlag(29, "DEX", "Defined synchronous exception on FP execution"),
                    new ControlRegisterFlag(26, "TFV", "Trapped Fault Valid"),
                    new ControlRegisterFlag(7, "IDF", "Input Denormal trapped"),
                    new ControlRegisterFlag(4, "IXF", "Inexact trapped"),
                    new ControlRegisterFlag(3, "UFF", "Underflow trapped"),
                    new ControlRegisterFlag(2, "OFF", "Overflow trapped"),
                    new ControlRegisterFlag(1, "DZF", "Divide by Zero trapped"),
                    new ControlRegisterFlag(0, "IOF", "Invalid Operation trapped")
                ), true).GetAsProtocol(ctx, true);

            retArray[i] = this.GetOrAddVariable(
                ReferenceUtils.MakeReference(ContainerType.ControlFlags, Arm.Register.FPSCR),
                () => new ControlRegisterVariable(Arm.Register.FPSCR, "FPSCR",
                    "FP Status and Control Register",
                    new ControlRegisterFlag(31, "N", "Negative"),
                    new ControlRegisterFlag(30, "Z", "Zero"),
                    new ControlRegisterFlag(29, "C", "Carry"),
                    new ControlRegisterFlag(28, "V", "Overflow"),
                    new ControlRegisterFlag(27, "QC", "Cumulative saturation"),
                    new ControlRegisterFlag(26, "AHP", "Alternative half-precision", "IEEE (0)", "Alternative (1)"),
                    new ControlRegisterFlag(25, "DN", "Default NaN"),
                    new ControlRegisterFlag(24, "FZ", "Flush-to-zero"),
                    new ControlRegisterFlag(22, 2, "RMode", "Rounding Mode", "To Nearest (00)", "Towards +Inf (01)",
                        "Towards -Inf (10)", "Towards Zero (11)"),
                    new ControlRegisterFlag(19, "FZ16", "Flush-to-zero mode on half-precision data-processing"),
                    new ControlRegisterFlag(15, "IDE", "Input Denormal trap enable"),
                    new ControlRegisterFlag(12, "IXE", "Inexact trap enable"),
                    new ControlRegisterFlag(11, "UFE", "Underflow trap enable"),
                    new ControlRegisterFlag(10, "OFE", "Overflow trap enable"),
                    new ControlRegisterFlag(9, "DZE", "Divide by Zero trap enable"),
                    new ControlRegisterFlag(8, "IOE", "Invalid Operation trap enable"),
                    new ControlRegisterFlag(7, "IDC", "Input Denormal exception"),
                    new ControlRegisterFlag(4, "IXC", "Inexact Cumulative exception"),
                    new ControlRegisterFlag(3, "UFC", "Underflow Cumulative exception"),
                    new ControlRegisterFlag(2, "OFC", "Overflow Cumulative exception"),
                    new ControlRegisterFlag(1, "DZC", "Divide by Zero Cumulative exception"),
                    new ControlRegisterFlag(0, "IOC", "Invalid Operation Cumulative exception")
                ), true).GetAsProtocol(ctx, true);
        }

        return retArray;
    }

    /// <summary>
    /// Creates Variables for general-purpose registers (R0 to R14). They also create children Variables that present
    /// a typed view over the register. These are specified by <see cref="DebuggerOptions.RegistersSubtypes"/>.
    /// Doesn't check if the debugger is initialized.
    /// </summary>
    private IEnumerable<Variable> MakeRegistersVariables(ValueFormat? format, int start, int count)
    {
        var end = start + count;
        var ctx = new VariableContext(_engine, _clientCulture, Options, format);
        var retArray = new Variable[count];

        for (var i = start; i < end; i++)
        {
            var regNumber = i;

            var unicornId = Arm.Register.GetRegister(i);
            var reference = ReferenceUtils.MakeReference(ContainerType.RegisterSubtypes, unicornId);
            var v = this.GetOrAddVariable(reference,
                () => new RegisterVariable(unicornId, $"R{regNumber}", Options.RegistersSubtypes,
                    Options.ShowFloatIeeeSubvariables), true);

            retArray[i - start] = v.GetAsProtocol(ctx, true);
        }

        return retArray;
    }

    /// <summary>
    /// Creates top-level SIMD/FP registers Variables. The topmost register length is controlled by
    /// <see cref="DebuggerOptions.TopSimdRegistersLevel"/>.
    /// Doesn't check if the debugger is initialized.
    /// </summary>
    /// <exception cref="InvalidOperationException"><see cref="DebuggerOptions.TopSimdRegistersLevel"/> is set to an invalid value.</exception>
    private IEnumerable<Variable> MakeSimdRegistersVariables(ValueFormat? format, int start, int count)
    {
        var end = start + count;
        var ctx = new VariableContext(_engine, _clientCulture, Options, format);
        var topLevel = Options.TopSimdRegistersLevel;
        var retArray = new Variable[count];

        for (var i = start; i < end; i++)
        {
            var regNumber = i;

            var unicornId = topLevel switch
            {
                SimdRegisterLevel.S32 => Arm.Register.GetSRegister(i),
                SimdRegisterLevel.D64 => Arm.Register.GetDRegister(i),
                SimdRegisterLevel.Q128 => Arm.Register.GetQRegister(i),
                _ => throw new ConfigurationException("Invalid TopSimdRegistersLevel.")
            };

            var reference =
                ReferenceUtils.MakeReference(ContainerType.SimdRegisterSubtypes, unicornId, 0, (int)topLevel);

            var v = this.GetOrAddVariable(reference,
                () => topLevel switch
                {
                    SimdRegisterLevel.S32 => new ArmSSimdRegisterVariable(regNumber, Options.SimdRegistersOptions),
                    SimdRegisterLevel.D64 => new ArmDSimdRegisterVariable(regNumber, Options.SimdRegistersOptions),
                    SimdRegisterLevel.Q128 => new ArmQSimdRegisterVariable(regNumber, Options.SimdRegistersOptions),
                    _ => throw new ConfigurationException("Invalid TopSimdRegistersLevel.")
                }, true);

            retArray[i - start] = v.GetAsProtocol(ctx, true);
        }

        return retArray;
    }

    /// <summary>
    /// Creates Variables for stack items. Always presumes that all values on the stack are 4 bytes long.
    /// Doesn't check if the debugger is initialized.
    /// </summary>
    private IEnumerable<Variable> MakeStackVariables(ValueFormat? format)
    {
        // IMPROVEMENT: Support other stack types

        var stack = this.GetStackSize();

        if (stack == 0)
            return Enumerable.Empty<Variable>();

        var retArray = new Variable[stack];
        var ctx = new VariableContext(_engine, _clientCulture, Options, format);

        for (var i = 0; i < stack; i += 4)
        {
            var fieldIndex = i;

            var address = (uint)(_engine.StackTopAddress - 4 - i);
            var reference = ReferenceUtils.MakeReference(ContainerType.StackSubtypes, address);
            var v = this.GetOrAddVariable(reference,
                () => new StackVariable(address, fieldIndex, Options.StackVariablesSubtypes,
                    Options.ShowFloatIeeeSubvariables), true);

            retArray[i / 4] = v.GetAsProtocol(ctx, true);
        }

        return retArray;
    }

    /// <summary>
    /// A data type specifier for data emitted by an assembler.
    /// </summary>
    private enum TypedSymbolType
    {
        /// <summary>
        /// 8 bits, .byte
        /// </summary>
        Byte = 1,

        /// <summary>
        /// 16 bits, .short, .hword
        /// </summary>
        Short,

        /// <summary>
        /// 32 bits, .word, .long, .int
        /// </summary>
        Int,

        /// <summary>
        /// 32 bits, .float, .single
        /// </summary>
        Float,

        /// <summary>
        /// 64 bits, .double
        /// </summary>
        Double,

        /// <summary>
        /// .asciz
        /// </summary>
        String
    }

    /// <summary>
    /// Describes a data symbol with recognized type. See <see cref="DebugProvider.DetermineDataSymbols"/>.
    /// </summary>
    private record struct TypedSymbol(string Name, uint Address, TypedSymbolType Type);

    private readonly List<TypedSymbol> _symbolsForVariables = new();

    /// <summary>
    /// Creates Variables for data symbols. Calls <see cref="DetermineDataSymbols"/> to determine the symbols and their
    /// types.
    /// Doesn't check if the debugger is initialized.
    /// </summary>
    private IEnumerable<Variable> MakeSymbolsVariables(ValueFormat? format)
    {
        if (_symbolsForVariables.Count == 0)
            this.DetermineDataSymbols();

        var ctx = new VariableContext(_engine, _clientCulture, Options, format);
        var retArray = new Variable[_symbolsForVariables.Count];
        var i = 0;

        foreach (var typedSymbol in _symbolsForVariables.Where(s => s.Type != TypedSymbolType.String))
        {
            var v = this.GetOrAddTopLevelVariable(typedSymbol.Name, () => new MemoryVariable(typedSymbol.Name,
                typedSymbol.Type switch
                {
                    TypedSymbolType.Byte => DebuggerVariableType.ByteU,
                    TypedSymbolType.Short => DebuggerVariableType.ShortU,
                    TypedSymbolType.Int => DebuggerVariableType.IntU,
                    TypedSymbolType.Float => DebuggerVariableType.Float,
                    TypedSymbolType.Double => DebuggerVariableType.Double,
                    _ => throw new Exception("Invalid debugger state: unexpected typed symbol type.")
                }, typedSymbol.Address));

            retArray[i++] = v.GetAsProtocol(ctx, true);
        }

        return retArray;
    }

    /// <summary>
    /// Recursively removes a given <see cref="IVariable"/> and its children from the variable cache.
    /// </summary>
    /// <param name="variable">The <see cref="IVariable"/> to remove.</param>
    private void RemoveVariable(IVariable variable)
    {
        if (variable.Reference == 0)
            return;

        _variables.Remove(variable.Reference);
        if (variable.Children != null)
        {
            foreach (var child in variable.Children.Values)
            {
                this.RemoveVariable(child);
            }
        }
    }

    /// <summary>
    /// Recursively stores a given <see cref="IVariable"/> and its children to the variable cache, identified by their
    /// Variables Reference numbers.
    /// </summary>
    /// <param name="variable">The <see cref="IVariable"/> to store.</param>
    private void AddOrUpdateVariable(IVariable variable)
    {
        if (variable.Reference == 0)
            return;

        if (_variables.ContainsKey(variable.Reference))
            this.RemoveVariable(variable);

        _variables[variable.Reference] = variable;

        if (variable.Children != null)
        {
            foreach (var child in variable.Children.Values)
            {
                this.AddOrUpdateVariable(child);
            }
        }
    }

    /// <summary>
    /// Retrieves an <see cref="IVariable"/> identified by a Variables Reference number.
    /// If it doesn't exist, invokes <paramref name="factory"/> to create it, and stores it and its children.
    /// </summary>
    /// <param name="reference">The Variables Reference number of the variable.</param>
    /// <param name="factory">A factory method to create the variable if it doesn't exist.</param>
    /// <param name="topLevel">If true, the created variable will be considered top-level (a direct descendant of a
    /// scope created by <see cref="MakeVariableScopes"/>) and also stored under its name which must be unique.</param>
    /// <returns>A cached or new instance of <see cref="IVariable"/>.</returns>
    /// <exception cref="InvalidOperationException">The provided <paramref cref="reference"/> doesn't correspond to the
    /// Variables Reference generated by an <see cref="IVariable"/> created by <paramref name="factory"/>.</exception>
    private IVariable GetOrAddVariable(long reference, Func<IVariable> factory, bool topLevel = false)
    {
        if (_variables.TryGetValue(reference, out var val))
            return val;

        var newVariable = factory();

        if (newVariable.Reference != reference)
            throw new InvalidOperationException("The reference of a created variable doesn't match the provided one.");

        this.AddOrUpdateVariable(newVariable);

        if (topLevel)
            _topLevel[newVariable.Name] = newVariable;

        return newVariable;
    }

    /// <summary>
    /// Retrieves a childless, top-level <see cref="IVariable"/> identified by its name.
    /// If it doesn't exist, invokes <paramref name="factory"/> to create it, and stores it.
    /// </summary>
    /// <remarks>
    /// A top-level variable is one that's a direct descendant of a scope created by <see cref="MakeVariableScopes"/>.
    /// It is globally identified by its name.
    /// This method is used to store such variables that don't have children so their Variables Reference is zero.
    /// Top-level variables with children must be accessed using <see cref="GetOrAddVariable"/> which also handles
    /// caching the children variables.
    /// </remarks>
    /// <param name="name">The name of the variable.</param>
    /// <param name="factory">A factory method to create the variable if it doesn't exist.</param>
    /// <returns>A cached or new instance of <see cref="IVariable"/>.</returns>
    /// <exception cref="InvalidOperationException">An <see cref="IVariable"/> created by <paramref name="factory"/>
    /// has a non-zero Variables Reference.</exception>
    private IVariable GetOrAddTopLevelVariable(string name, Func<IVariable> factory)
    {
        if (_topLevel.TryGetValue(name, out var val))
            return val;

        var newVariable = factory();

        if (newVariable.Reference != 0)
            throw new InvalidOperationException("The reference of a created top-level sole variable isn't 0.");

        _topLevel[newVariable.Name] = newVariable;

        return newVariable;
    }

    private bool TryResolveTopVariable(long variablesReference, string varName)
    {
        var containerType = ReferenceUtils.GetContainerType(variablesReference);
        if (containerType is ContainerType.Registers)
        {
            if (!int.TryParse(varName.AsSpan(1), out var regNum))
                return false;

            var regId = Arm.Register.GetRegister(regNum);
            var reference = ReferenceUtils.MakeReference(ContainerType.RegisterSubtypes, regId);
            this.GetOrAddVariable(reference,
                () => new RegisterVariable(regId, varName, Options.RegistersSubtypes,
                    Options.ShowFloatIeeeSubvariables), true);

            return true;
        }

        if (containerType is ContainerType.RegisterSubtypes or ContainerType.RegisterSubtypesValues)
        {
            var regId = ReferenceUtils.GetRegisterId(variablesReference);
            var regNum = Arm.Register.GetRegisterNumber(regId);
            var reference = ReferenceUtils.MakeReference(ContainerType.RegisterSubtypes, regId);
            this.GetOrAddVariable(reference,
                () => new RegisterVariable(regId, $"R{regNum}", Options.RegistersSubtypes,
                    Options.ShowFloatIeeeSubvariables), true);

            return true;
        }

        if (containerType == ContainerType.SimdRegisters)
        {
            if (!int.TryParse(varName.AsSpan(1), out var regNum))
                return false;

            this.MakeSimdRegistersVariables(null, regNum, 1);

            return true;
        }

        if (containerType is ContainerType.SimdRegisterSubtypes or ContainerType.SimdRegisterSubtypesValues)
        {
            var regId = ReferenceUtils.GetRegisterId(variablesReference);
            var level = ReferenceUtils.GetSimdLevel(variablesReference);
            var regNum = (SimdRegisterLevel)level switch
            {
                SimdRegisterLevel.D64 => Arm.Register.GetDRegisterNumber(regId),
                SimdRegisterLevel.Q128 => Arm.Register.GetQRegisterNumber(regId),
                _ => Arm.Register.GetSRegisterNumber(regId)
            };

            var levelDiff = (int)Options.TopSimdRegistersLevel - level;
            if (levelDiff < 0)
            {
                var reference = ReferenceUtils.MakeReference(ContainerType.SimdRegisterSubtypes, regId, 0, level);
                switch ((SimdRegisterLevel)level)
                {
                    case SimdRegisterLevel.D64:
                        this.GetOrAddVariable(reference,
                            () => new ArmDSimdRegisterVariable(regNum, Options.SimdRegistersOptions), true);

                        break;
                    case SimdRegisterLevel.Q128:
                        this.GetOrAddVariable(reference,
                            () => new ArmQSimdRegisterVariable(regNum, Options.SimdRegistersOptions), true);

                        break;
                    default:
                        throw new ArgumentOutOfRangeException();
                }

                return true;
            }

            if (levelDiff > 0)
                regNum /= (2 * levelDiff);

            if ((Options.TopSimdRegistersLevel == SimdRegisterLevel.D64 && regNum > 31) || regNum > 15)
                return false;

            this.MakeSimdRegistersVariables(null, regNum, 1);

            return true;
        }

        if (containerType is ContainerType.Symbols)
        {
            this.MakeSymbolsVariables(null);

            return _topLevel.ContainsKey(varName);
        }

        if (containerType is ContainerType.Stack or ContainerType.StackSubtypes or ContainerType.StackSubtypesValues)
        {
            this.MakeStackVariables(null);

            if (_variables.TryGetValue(variablesReference, out var container))
                return container.Children?.ContainsKey(varName) ?? false;

            return false;
        }

        if (containerType is ContainerType.ControlRegisters or ContainerType.ControlFlags)
        {
            this.MakeControlRegistersVariables(null);

            return containerType is ContainerType.ControlRegisters
                ? _topLevel.ContainsKey(varName)
                : (_variables.TryGetValue(variablesReference, out var variable) &&
                    (variable.Children?.ContainsKey(varName) ?? false));
        }

        return false;
    }

    private string GetVariableName(IVariable variable)
    {
        var st = new Stack<IVariable>();
        var sb = new StringBuilder();

        var v = variable;
        while (v != null)
        {
            st.Push(v);
            v = v.Parent;
        }

        while (st.Count != 0)
        {
            v = st.Pop();
            sb.Append(v.Name);
            sb.Append('.');
        }

        return sb.ToString();
    }

    /// <summary>
    /// Returns the difference between SP and stack top in bytes.
    /// Returns 0 if the value of SP indicates it is not used as the stack pointer.
    /// </summary>
    private uint GetStackSize()
    {
        if (_engine.Options.StackPointerType != StackPointerType.FullDescending)
            return 0; // TODO: support other stack types?

        var top = _engine.StackTopAddress;
        var currentSp = _engine.Engine.RegRead<uint>(Arm.Register.SP);

        if (currentSp > top)
            return 0;

        return top - currentSp;
    }

    /// <summary>
    /// Goes through the loaded executable's symbol table and attempts to determine the types of symbols defined in the
    /// data section based on the assembly listing and linker map. Fills <see cref="_symbolsForVariables"/> with records
    /// of symbols' names, addresses and determined types.
    /// </summary>
    private void DetermineDataSymbols()
    {
        var exe = Executable;

        if (exe.Elf.Sections.FirstOrDefault(s => s.Type == SectionType.SymbolTable) is not SymbolTable<uint> symTab)
            return;

        var dataSection = exe.Elf.Sections.FirstOrDefault(s => s.Name == ".data");

        if (dataSection == null)
            return;

        var symbols = symTab.Entries.Where(s => s.Type is SymbolType.Object or SymbolType.NotSpecified)
                            .Where(s => s.PointedSection == dataSection && !s.Name.StartsWith('$'))
                            .GroupBy(s => s.Value)
                            .ToDictionary(s => s.Key, s => s);

        for (var objectIndex = 0; objectIndex < exe.SourceObjects.Count; objectIndex++)
        {
            var dataBaseAddress = exe.DataSectionStarts[objectIndex];

            if (dataBaseAddress == -1)
                continue;

            var dataBaseAddressU = (uint)dataBaseAddress;

            var obj = exe.SourceObjects[objectIndex];
            foreach (var (objectAddress, type) in obj.PossibleDataFields)
            {
                var actualAddress = dataBaseAddressU + objectAddress;

                if (!symbols.TryGetValue(actualAddress, out var symbolsOnAddress))
                    continue;

                symbols.Remove(actualAddress);
                foreach (var sym in symbolsOnAddress)
                {
                    var symbol = new TypedSymbol(sym.Name, sym.Value, type switch
                    {
                        "float" or "single" => TypedSymbolType.Float,
                        "double" => TypedSymbolType.Double,
                        "word" or "long" or "int" => TypedSymbolType.Int,
                        "short" or "hword" => TypedSymbolType.Short,
                        "byte" => TypedSymbolType.Byte,
                        "asciz" => TypedSymbolType.String,
                        _ => 0
                    });

                    if (symbol.Type != 0)
                        _symbolsForVariables.Add(symbol);
                }
            }
        }
    }

    #endregion

    #region Memory

    private (uint StartAddress, uint EndAddress) DetermineMappedMemoryRegion(uint startAddress, int targetCount)
    {
        var endAddress = (uint)(startAddress + targetCount);
        MemorySegment? startSegment = null;
        MemorySegment? endSegment = null;

        foreach (var segment in _engine.Segments)
        {
            if (segment.StartAddress <= startAddress && segment.EndAddress > startAddress)
                startSegment = segment;

            if (segment.StartAddress <= endAddress && segment.EndAddress >= endAddress)
                endSegment = segment;
        }

        if (startSegment == null)
        {
            var target = startAddress;
            foreach (var segment in _engine.Segments.OrderBy(s => s.StartAddress))
            {
                if (segment.StartAddress > target)
                {
                    startAddress = segment.StartAddress;
                    startSegment = segment;

                    break;
                }
            }

            if (startSegment == null)
                return (0, 0);
        }

        if (startSegment == endSegment ||
            startSegment.EndAddress == endSegment?.StartAddress) // Continuous block of memory
            return (startAddress, endAddress);

        return (startAddress, startSegment.EndAddress);
    }

    public ReadMemoryResponse ReadMemory(string memoryReference, long count, long? offset)
    {
        if (!FormattingUtils.TryParseAddress(memoryReference, out var address))
            throw new InvalidMemoryReferenceException();

        if (offset.HasValue)
            address = (uint)(address + offset.Value);

        if (count is < 0 or > int.MaxValue)
            throw new InvalidMemoryOperationException(ExceptionMessages.InvalidMemorySize);

        var mappedRegion = this.DetermineMappedMemoryRegion(address, (int)count);
        var actualCount = (int)(mappedRegion.EndAddress - mappedRegion.StartAddress);

        if (mappedRegion.StartAddress == mappedRegion.EndAddress && mappedRegion.EndAddress == 0)
            return new ReadMemoryResponse() { Address = string.Empty, UnreadableBytes = count };

        address = mappedRegion.StartAddress;

        var bufferSize = Base64.GetMaxEncodedToUtf8Length(actualCount);
        bufferSize = Math.Max(bufferSize, actualCount);

        byte[]? rentedBytes = null;

        try
        {
            if (count < ExecutionEngine.MaxStackAllocatedSize)
            {
                Span<byte> bytes = stackalloc byte[bufferSize];
                _engine.Engine.MemRead(address, bytes, (nuint)actualCount);

                return this.ReadMemory(address, bytes, count, actualCount);
            }
            else if (count < ExecutionEngine.MaxArrayPoolSize)
            {
                var bytes = _engine.ArrayPool.Rent(bufferSize);
                rentedBytes = bytes;
                _engine.Engine.MemRead(address, bytes, (nuint)actualCount);

                var resp = this.ReadMemory(address, bytes, count, actualCount);

                return resp;
            }
            else
            {
                var bytes = new byte[bufferSize];
                _engine.Engine.MemRead(address, bytes, (nuint)count);

                return this.ReadMemory(address, bytes, count, actualCount);
            }
        }
        catch (UnicornException e)
        {
            throw new InvalidMemoryOperationException(ExceptionMessages.InvalidMemoryRead, e);
        }
        finally
        {
            if (rentedBytes != null)
                _engine.ArrayPool.Return(rentedBytes);
        }
    }

    private ReadMemoryResponse ReadMemory(uint address, Span<byte> bytes, long requestedCount, int actualCount)
    {
        if (Base64.EncodeToUtf8InPlace(bytes, actualCount, out var written) != OperationStatus.Done)
            throw new Exception(); // Shouldn't happen

        var encoded = Encoding.UTF8.GetString(bytes[..written]);

        return new ReadMemoryResponse()
        {
            Address = FormattingUtils.FormatAddress(address),
            Data = encoded,
            //UnreadableBytes = requestedCount - actualCount
        };
    }

    public WriteMemoryResponse WriteMemory(string memoryReference, bool allowPartial, long? offset, string dataEncoded)
    {
        if (!FormattingUtils.TryParseAddress(memoryReference, out var address))
            throw new InvalidMemoryReferenceException();

        if (offset.HasValue)
            address = (uint)(address + offset.Value);

        var utfByteCount = Encoding.UTF8.GetByteCount(dataEncoded);
        var rented = utfByteCount <= ExecutionEngine.MaxArrayPoolSize;
        var bytes = rented ? _engine.ArrayPool.Rent(utfByteCount) : new byte[utfByteCount];

        Encoding.UTF8.GetBytes(dataEncoded, bytes);

        if (Base64.DecodeFromUtf8InPlace(bytes[..utfByteCount], out var dataSize) != OperationStatus.Done)
            throw new Exception(); // Shouldn't happen

        var mappedRegion = this.DetermineMappedMemoryRegion(address, dataSize);
        var mappedSize = (int)(mappedRegion.EndAddress - mappedRegion.StartAddress);

        if (mappedSize < dataSize && !allowPartial)
            throw new InvalidMemoryOperationException(ExceptionMessages.InvalidMemoryWrite);

        try
        {
            _engine.Engine.MemWrite(mappedRegion.StartAddress, bytes, (nuint)mappedSize);
        }
        catch (UnicornException e)
        {
            throw new InvalidMemoryOperationException(ExceptionMessages.InvalidMemoryWrite, e);
        }

        return new WriteMemoryResponse()
        {
            BytesWritten = mappedSize
        };
    }

    #endregion

    #region Sources

    public async Task<SourceResponse> GetSourceContents(long sourceReference)
    {
        sourceReference -= 1; // Source references are indices in the executable sources array offset by +1

        var exeSources = Executable.Sources;

        if (exeSources.Count <= sourceReference)
            throw new InvalidSourceException();

        var exeSource = exeSources[(int)sourceReference];
        using var locatedFile = await exeSource.SourceFile.LocateAsync();
        var contents = await File.ReadAllTextAsync(locatedFile.FileSystemPath);

        return new SourceResponse() { Content = contents };
    }

    public async Task<SourceResponse> GetSourceContents(Source source)
    {
        var reference = this.GetSourceReference(source);

        return await this.GetSourceContents(reference);
    }

    public async Task<IEnumerable<Source>> GetSources()
    {
        var exeSources = Executable.Sources;

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
        var exeSources = Executable.Sources;

        // Source references are indices in the executable sources array offset by +1
        try
        {
            var reference = this.GetSourceReference(source) - 1;

            return exeSources.Count <= reference ? null : exeSources[reference].BuildPath;
        }
        catch (InvalidSourceException)
        {
            return null;
        }
    }

    public AssembledObject? GetObjectForSource(Source source)
    {
        var exeSourceObjects = Executable.SourceObjects;

        // Source references are indices in the executable sources array offset by +1
        try
        {
            var reference = this.GetSourceReference(source) - 1;

            return exeSourceObjects.Count <= reference ? null : exeSourceObjects[reference];
        }
        catch (InvalidSourceException)
        {
            return null;
        }
    }

    private int GetSourceReference(Source? source)
    {
        if (source?.SourceReference is > 0)
            return (int)source.SourceReference.Value;

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
            throw new InvalidSourceException();

        var i = 1;
        foreach (var exeSource in Executable.Sources)
        {
            if (exeSource.ClientPath == null || source.Path == null)
                continue;

            // TODO: Handle path case sensitivity?
            if (exeSource.ClientPath.Equals(source.Path, StringComparison.OrdinalIgnoreCase))
                return i;

            i++;
        }

        throw new InvalidSourceException();
    }

    internal async Task<Source> GetSource(int sourceIndex)
    {
        return await this.GetSource(sourceIndex, _engine.ExecutableInfo!.Sources[sourceIndex]);
    }

    internal async Task<Source> GetSource(int sourceIndex, ExecutableSource exeSource)
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
