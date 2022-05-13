// DebugProvider.cs
// Author: Ondřej Ondryáš

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.Debugger;
using Code4Arm.ExecutionCore.Execution.Exceptions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Constants;
using ELFSharp.ELF.Sections;
using MediatR;
using Newtonsoft.Json.Linq;

namespace Code4Arm.ExecutionCore.Execution;

internal class DebugProvider : IDebugProvider, IDebugProtocolSourceLocator
{
    private readonly ExecutionEngine _engine;
    private readonly IUnicorn _unicorn;
    private InitializeRequestArguments? _clientInfo;
    private CultureInfo? _clientCulture;

    private Dictionary<long, IVariable> _variables = new();
    private Dictionary<string, IVariable> _topLevel = new();

    public DebugProvider(ExecutionEngine engine, DebuggerOptions options, IMediator mediator)
    {
        _engine = engine;
        _unicorn = engine.Engine;
        Options = options;
    }

    public DebuggerOptions Options { get; set; }

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
            SupportsSetExpression = true,
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
        // TODO
        return new[]
        {
            new ExceptionBreakpointsFilter()
                { Label = "All Unicorn exceptions", Filter = "all", SupportsCondition = false }
        };
    }

    public IEnumerable<DisassembledInstruction> Disassemble(string memoryReference, long? byteOffset,
        long? instructionOffset, long instructionCount,
        bool resolveSymbols) =>
        throw new NotImplementedException();

    public IEnumerable<GotoTarget> GetGotoTargets(Source source, long line, long? column)
    {
        throw new NotImplementedException();
    }


    public DataBreakpointInfoResponse GetDataBreakpointInfo(long containerId, string variableName) =>
        throw new NotImplementedException();

    public DataBreakpointInfoResponse GetDataBreakpointInfo(string expression) => throw new NotImplementedException();

    public ExceptionInfoResponse GetLastExceptionInfo() => throw new NotImplementedException();

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

        var ret = new StackTraceResponse() { StackFrames = new Container<StackFrame>(frames), TotalFrames = 1 };

        return ret;
    }

    public IEnumerable<BreakpointLocation> GetBreakpointLocations(Source source, int line, int? endLine) =>
        throw new NotImplementedException();

    public IEnumerable<ExceptionBreakpointsFilter> GetExceptionBreakpointFilters() =>
        throw new NotImplementedException();

    #region Expressions

    public SetExpressionResponse SetExpression(string expression, string value, ValueFormat? format)
    {
        if (expression.StartsWith("!!!") && expression.Length > 3)
        {
            var divider = expression.IndexOf('!', 3);
            var referenceSpan = expression.AsSpan(3, (divider == -1 ? expression.Length : divider) - 3);

            if (!long.TryParse(referenceSpan, out var reference))
                throw new InvalidExpressionException();

            if (!_variables.TryGetValue(reference, out var toSet))
                throw new InvalidExpressionException();

            if (divider != -1)
            {
                var childName = expression[(divider + 1)..];

                if (!(toSet.Children?.TryGetValue(childName, out toSet) ?? false))
                    throw new InvalidExpressionException();
            }

            var ctx = new VariableContext(_engine, _clientCulture!, Options, format);
            toSet.Set(value, ctx);

            while (toSet.IsViewOfParent)
            {
                if (toSet.Parent == null)
                    break;

                toSet = toSet.Parent;
            }

            toSet.Evaluate(ctx);
            var val = toSet.Get(ctx);

            return new SetExpressionResponse()
            {
                Type = toSet.Type,
                Value = val,
                VariablesReference = toSet.Reference
            };
        }

        throw new InvalidExpressionException();
    }

    private Regex _exprRegex =
        new(
            @"^(?:\((?<type>[\w ]*?)\))?\s*\[\s*(?:(?:R(?<base>[0-9]{1,2}))|(?<baseA>(?:0x[\da-fA-F]+)|(?:\d+)|(?:\w+)))(?:\s*,\s*(?:(?<regofSign>[+-])?R(?<regoof>[0-9]{1,2})(?:\s*,\s*(?<shift>LSL|LSR|ASR|ROR)\s+(?<shImm>\d+))?|(?:(?<immofSign>[+-])?(?<immof>\d+))))?\s*\]",
            RegexOptions.Compiled);

    public EvaluateResponse EvaluateExpression(string expression, EvaluateArgumentsContext? context,
        ValueFormat? format)
    {
        if (expression.StartsWith("!!!") && expression.Length > 3)
        {
            var divider = expression.IndexOf('!', 3);
            var referenceSpan = expression.AsSpan(3, (divider == -1 ? expression.Length : divider) - 3);

            if (!long.TryParse(referenceSpan, out var reference))
                throw new InvalidExpressionException();

            if (!_variables.TryGetValue(reference, out var toSet))
                throw new InvalidExpressionException();

            if (divider != -1)
            {
                var childName = expression[(divider + 1)..];

                if (!(toSet.Children?.TryGetValue(childName, out toSet) ?? false))
                    throw new InvalidExpressionException();
            }

            var ctx = new VariableContext(_engine, _clientCulture!, Options, format);
            var value = toSet.GetEvaluated(ctx);

            return new EvaluateResponse()
            {
                Result = value,
                Type = toSet.Type,
                VariablesReference = toSet.Reference,
                NamedVariables = toSet.Children?.Count ?? 0
            };
        }

        // Register expression variants:
        // [Rx]
        // [Rx, +-Ry]
        // [Rx, +-Ry, shift imm]
        // [Rx, +-imm]
        // type prefixes: (float) (double) (byte) (short) (int) (long) & unsig. variants & (string) - reads a C-string

        // Direct addressing: 
        // [address/symbol]
        // [address/symbol, +-Ry]
        // [address/symbol, +-Ry, shift imm]
        // type prefixes: same as above

        // Register access:
        // Rx / Sx / Qx / Dx
        // {anything defined in Arm.Registers}
        // !{unicorn reg id}
        // type prefixes: same as above without (string).

        // all expressions may end with a display format specifier:
        // :x (unsigned hex)
        // :b (binary)
        // :ieee (only for 32b and 64b values -> show sign/exponent/mantissa
        // if type prefix is string, this has no effect

        var match = _exprRegex.Match(expression);

        if (!match.Success)
            throw new InvalidExpressionException();

        // TODO
        return new EvaluateResponse() { Result = "test" };
    }

    #endregion

    #region Variables

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
        IVariable targetVariable;

        if (ReferenceUtils.IsTopLevelContainer(containerId))
        {
            if (!_topLevel.TryGetValue(variableName, out targetVariable!))
                throw new InvalidVariableReferenceException();
        }
        else
        {
            if (!_variables.TryGetValue(containerId, out var parentVariable))
                throw new InvalidVariableReferenceException();

            if (!(parentVariable.Children?.TryGetValue(variableName, out targetVariable!) ?? false))
                throw new InvalidVariableReferenceException();
        }

        var ctx = new VariableContext(_engine, _clientCulture!, Options, format);
        targetVariable.Set(value, ctx);

        targetVariable.Evaluate(ctx);

        return new SetVariableResponse()
        {
            Value = targetVariable.Get(ctx),
            Type = targetVariable.Type,
            NamedVariables = targetVariable.Children?.Count,
            VariablesReference = targetVariable.Reference
        };
    }

    public ScopesResponse MakeVariableScopes()
    {
        var ret = new List<Scope>();

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

    public IEnumerable<Variable> GetChildVariables(long variablesReference, long? start, long? count,
        ValueFormat? format)
    {
        if (_variables.TryGetValue(variablesReference, out var variable) && variable.Children != null)
        {
            var ctx = new VariableContext(_engine, _clientCulture!, Options, format);

            if (variable.IsViewOfParent || variable.Children.Any(v => v.Value.IsViewOfParent))
                variable.Evaluate(ctx);

            return variable.Children.Values.Select(v =>
                v.GetAsProtocol(ctx, !v.IsViewOfParent));
        }

        var containerType = (ContainerType)(variablesReference & 0xF);
        var ret = new List<Variable>();

        switch (containerType)
        {
            case ContainerType.Registers:
                this.MakeRegistersVariables(ret, format, (int)(start ?? 0), (int)(count ?? 15));

                break;
            case ContainerType.ControlRegisters:
                this.MakeControlRegistersVariables(ret, format);

                break;
            case ContainerType.SimdRegisters:
                this.MakeSimdRegistersVariables(ret, format, (int)(start ?? 0), (int)(count ?? 16));

                break;
            case ContainerType.Symbols:
                this.MakeSymbolsVariables(ret, format);

                break;
            case ContainerType.Stack:
                this.MakeStackVariables(ret, format);

                break;
            case ContainerType.SimdRegisterSubtypes:
            case ContainerType.SimdRegisterSubtypesValues:
            case ContainerType.StackSubtypes:
            case ContainerType.StackSubtypesValues:
            case ContainerType.ControlFlags:
            case ContainerType.RegisterSubtypes:
            case ContainerType.RegisterSubtypesValues:
            default:
                throw new InvalidVariableReferenceException();
        }

        return ret;
    }

    private void MakeControlRegistersVariables(List<Variable> ret, ValueFormat? format)
    {
        var ctx = new VariableContext(_engine, _clientCulture!, Options, format);

        ret.Add(this.GetOrAddVariable(ReferenceUtils.MakeReference(ContainerType.ControlFlags, Arm.Register.APSR),
            () => new ControlRegisterVariable(Arm.Register.APSR, "APSR", "Application Processor State Register",
                new ControlRegisterFlag(31, "N", "Negative"),
                new ControlRegisterFlag(30, "Z", "Zero"),
                new ControlRegisterFlag(29, "C", "Carry"),
                new ControlRegisterFlag(28, "V", "Overflow"),
                new ControlRegisterFlag(27, "Q", "Cumulative saturation"),
                new ControlRegisterFlag(16, 4, "GE", "Greater than or Equal")
            ), true).GetAsProtocol(ctx, true));

        ret.Add(this.GetOrAddTopLevelVariable("PC",
                        () => new UnstructuredRegisterVariable(Arm.Register.PC, "PC", "Program Counter (R15)"))
                    .GetAsProtocol(ctx, true));

        if (Options.EnableExtendedControlVariables)
        {
            ret.Add(this.GetOrAddVariable(ReferenceUtils.MakeReference(ContainerType.ControlFlags, Arm.Register.CPSR),
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
                ), true).GetAsProtocol(ctx, true));

            ret.Add(this.GetOrAddVariable(ReferenceUtils.MakeReference(ContainerType.ControlFlags, Arm.Register.FPEXC),
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
                ), true).GetAsProtocol(ctx, true));

            ret.Add(this.GetOrAddVariable(ReferenceUtils.MakeReference(ContainerType.ControlFlags, Arm.Register.FPSCR),
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
                ), true).GetAsProtocol(ctx, true));
        }
    }

    private void MakeRegistersVariables(List<Variable> ret, ValueFormat? format, int start, int count)
    {
        var end = start + count;
        var ctx = new VariableContext(_engine, _clientCulture!, Options, format);

        for (var i = start; i < end; i++)
        {
            var regNumber = i;

            var unicornId = Arm.Register.GetRegister(i);
            var reference = ReferenceUtils.MakeReference(ContainerType.RegisterSubtypes, unicornId);
            var v = this.GetOrAddVariable(reference,
                () => new RegisterVariable(unicornId, $"R{regNumber}", Options.RegistersSubtypes), true);

            ret.Add(v.GetAsProtocol(ctx, true));
        }
    }

    private void MakeSimdRegistersVariables(List<Variable> ret, ValueFormat? format, int start, int count)
    {
        var end = start + count;
        var ctx = new VariableContext(_engine, _clientCulture!, Options, format);
        var topLevel = Options.TopSimdRegistersLevel;

        for (var i = start; i < end; i++)
        {
            var regNumber = i;

            var unicornId = topLevel switch
            {
                SimdRegisterLevel.S32 => Arm.Register.GetSRegister(i),
                SimdRegisterLevel.D64 => Arm.Register.GetDRegister(i),
                SimdRegisterLevel.Q128 => Arm.Register.GetQRegister(i),
                _ => throw new InvalidOperationException()
            };

            var reference =
                ReferenceUtils.MakeReference(ContainerType.SimdRegisterSubtypes, unicornId, 0, (int)topLevel);

            var v = this.GetOrAddVariable(reference,
                () => topLevel switch
                {
                    SimdRegisterLevel.S32 => new ArmSSimdRegisterVariable(regNumber),
                    SimdRegisterLevel.D64 => new ArmDSimdRegisterVariable(regNumber),
                    SimdRegisterLevel.Q128 => new ArmQSimdRegisterVariable(regNumber),
                    _ => throw new ArgumentOutOfRangeException()
                }, true);

            ret.Add(v.GetAsProtocol(ctx, true));
        }
    }

    private void MakeStackVariables(List<Variable> ret, ValueFormat? format)
    {
        // TODO: support other stack types?

        var stack = this.GetStackSize();

        if (stack == 0)
            return;

        var ctx = new VariableContext(_engine, _clientCulture!, Options, format);

        for (var i = 0; i < stack; i += 4)
        {
            var fieldIndex = i;

            var address = (uint)(_engine.StackTopAddress - 4 - i);
            var reference = ReferenceUtils.MakeReference(ContainerType.StackSubtypes, address);
            var v = this.GetOrAddVariable(reference,
                () => new StackVariable(address, fieldIndex, Options.StackVariablesSubtypes), true);

            ret.Add(v.GetAsProtocol(ctx, true));
        }
    }

    private enum TypedSymbolType
    {
        Byte,
        Short,
        Int,
        Float,
        Double,
        String
    }

    private record struct TypedSymbol(string Name, uint Address, TypedSymbolType Type);
    private List<TypedSymbol> _symbolsForVariables = new();

    private void MakeSymbolsVariables(List<Variable> ret, ValueFormat? format)
    {
        if (_symbolsForVariables.Count == 0)
            this.DetermineDataSymbols();

        var ctx = new VariableContext(_engine, _clientCulture!, Options, format);
        // TODO
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
                    _ => throw new ArgumentOutOfRangeException()
                }, typedSymbol.Address));

            ret.Add(v.GetAsProtocol(ctx, true));
        }
    }

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

    private void DetermineDataSymbols()
    {
        if (_engine.ExecutableInfo is not Executable exe)
            return;

        if (exe.Elf.Sections.FirstOrDefault(s => s.Type == SectionType.SymbolTable) is not SymbolTable<uint> symTab)
            return;

        var dataSection = exe.Elf.Sections.FirstOrDefault(s => s.Name == ".data");

        if (dataSection == null)
            return;

        var symbols = symTab.Entries.Where(s => s.Type is SymbolType.Object or SymbolType.NotSpecified)
                            .Where(s => s.PointedSection == dataSection && !s.Name.StartsWith('$'))
                            .GroupBy(s => s.Value)
                            .ToDictionary(s => s.Key, s => s);

        for (var objI = 0; objI < exe.SourceObjects.Count; objI++)
        {
            var dataBaseAddress = exe.DataSectionStarts[objI];

            if (dataBaseAddress == -1)
                continue;

            var dataBaseAddressU = (uint)dataBaseAddress;

            var obj = exe.SourceObjects[objI];
            foreach (var (address, type) in obj.PossibleDataFields)
            {
                var a = dataBaseAddressU + address;
                if (symbols.TryGetValue(a, out var syms))
                {
                    symbols.Remove(a);
                    foreach (var sym in syms)
                    {
                        _symbolsForVariables.Add(new TypedSymbol(sym.Name, sym.Value, type switch
                        {
                            "float" or "single" => TypedSymbolType.Float,
                            "double" => TypedSymbolType.Double,
                            "word" or "long" or "int" => TypedSymbolType.Int,
                            "short" or "hword" => TypedSymbolType.Short,
                            "byte" => TypedSymbolType.Byte,
                            "ascii" or "asciz" => TypedSymbolType.String,
                            _ => throw new InvalidOperationException()
                        }));
                    }
                }
            }
        }
    }

    #endregion

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

        var exeSource = exeSources[(int)sourceReference];
        using var locatedFile = await exeSource.SourceFile.LocateAsync();
        var contents = await File.ReadAllTextAsync(locatedFile.FileSystemPath);

        return new SourceResponse() { Content = contents };
    }

    private int GetSourceReference(Source? source, [CallerMemberName] string caller = "")
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
