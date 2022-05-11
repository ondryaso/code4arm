// DebugProvider.cs
// Author: Ondřej Ondryáš

using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
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
    private CultureInfo? _clientCulture;

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
            string newVal;

            if (int.TryParse(value, isHex ? NumberStyles.HexNumber : NumberStyles.Integer,
                    NumberFormatInfo.InvariantInfo, out var val))
            {
                _engine.Engine.RegWrite(Arm.Register.GetRegister(regId), val);
                newVal = val.ToString(isHex ? "x" : "");
            }
            else if (uint.TryParse(value, isHex ? NumberStyles.HexNumber : NumberStyles.Integer,
                         NumberFormatInfo.InvariantInfo, out var valU))
            {
                _engine.Engine.RegWrite(Arm.Register.GetRegister(regId), valU);
                newVal = valU.ToString(isHex ? "x" : "");
            }
            else if (float.TryParse(value, out var valF))
            {
                _engine.Engine.RegWrite(Arm.Register.GetRegister(regId), valF);
                newVal = valF.ToString();
            }
            else
            {
                throw new InvalidValueException();
            }

            return new SetVariableResponse()
            {
                Value = newVal,
                Type = "General-purpose register",
                VariablesReference = 1000 + regId
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
            @"^(?:\((?<type>[\w ]*?)\))?\s*\[\s*(?:(?:R(?<base>[0-9]{1,2}))|(?<baseA>(?:0x[\da-fA-F]+)|(?:\d+)|(?:\w+)))(?:\s*,\s*(?:(?<regofSign>[+-])?R(?<regoof>[0-9]{1,2})(?:\s*,\s*(?<shift>LSL|LSR|ASR|ROR)\s+(?<shImm>\d+))?|(?:(?<immofSign>[+-])?(?<immof>\d+))))?\s*\]",
            RegexOptions.Compiled);

    public EvaluateResponse EvaluateExpression(string expression, EvaluateArgumentsContext? context,
        ValueFormat? format)
    {
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
        // if type prefix is string, this has no effect

        var match = _exprRegex.Match(expression);

        if (!match.Success)
            throw new InvalidExpressionException();

        // TODO

        uint address;
        if (!match.Groups["base"].Success || match.Groups["base"].Value.Length == 0)
        {
            var addrStr = match.Groups["baseA"].Value;
            var style = NumberStyles.None;

            if (addrStr.StartsWith("0x"))
            {
                addrStr = addrStr[2..];
                style = NumberStyles.HexNumber;
            }

            if (!uint.TryParse(addrStr, style, null, out address))
                throw new InvalidExpressionException();
        }
        else
        {
            var regStr = match.Groups["base"].Value;

            if (!int.TryParse(regStr, out var reg) || reg < 0 || reg > 15)
                throw new InvalidExpressionException();

            address = _engine.Engine.RegRead<uint>(Arm.Register.GetRegister(reg));
        }

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

    private enum ContainerType : uint
    {
        Registers = 1,
        ControlRegisters,
        SimdRegisters,
        Symbols,
        Stack,

        RegisterSubtypes,
        RegisterSubtypesValues,
        SimdRegisterSubtypes,
        SimdRegisterSubtypesValues,

        ControlFlags,

        StackSubtypes,
        StackSubtypesValues
    }

    private enum Subtype : uint
    {
        ByteU = 0,
        ByteS,
        ShortU,
        ShortS,
        IntU,
        IntS,
        LongU,
        LongS,
        Float,
        Double
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

    public ScopesResponse MakeVariableScopes()
    {
        var ret = new List<Scope>();

        if (Options.EnableRegistersVariables)
        {
            ret.Add(new Scope()
            {
                Name = "Registers",
                NamedVariables = 14,
                VariablesReference = MakeReference(ContainerType.Registers),
                PresentationHint = "registers"
            });
        }

        if (Options.EnableControlVariables)
        {
            // Basic: PC, APSR, FPSCR
            // Extended: + CPSR, FPEXC, FPINST, FPINST2, FPSID, MVFR0-2 
            var count = Options.EnableExtendedControlVariables ? 11 : 3;

            ret.Add(new Scope()
            {
                Name = "CPU state",
                NamedVariables = count,
                VariablesReference = MakeReference(ContainerType.ControlRegisters),
                PresentationHint = "registers"
            });
        }

        if (Options.EnableSimdVariables)
        {
            ret.Add(new Scope()
            {
                Name = "SIMD/FP registers",
                NamedVariables = 16,
                VariablesReference = MakeReference(ContainerType.SimdRegisters),
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
                    VariablesReference = MakeReference(ContainerType.Stack),
                    PresentationHint = "locals"
                });
            }
        }

        if (Options.EnableAutomaticDataVariables)
        {
            // TODO   
        }

        return new ScopesResponse()
        {
            Scopes = new Container<Scope>(ret)
        };
    }

    public IEnumerable<BreakpointLocation> GetBreakpointLocations(Source source, int line, int? endLine) =>
        throw new NotImplementedException();

    public IEnumerable<ExceptionBreakpointsFilter> GetExceptionBreakpointFilters() =>
        throw new NotImplementedException();

    private void MakeControlRegistersVariables(List<Variable> ret)
    {
        var apsr = _engine.Engine.RegRead<uint>(Arm.Register.APSR);
        ret.Add(new Variable()
        {
            Name = "APSR",
            Type = "Application Processor State Register",
            Value = $"0x{apsr:x}",
            VariablesReference = MakeReference(ContainerType.ControlFlags, Arm.Register.APSR)
        });

        var pc = _engine.Engine.RegRead<uint>(Arm.Register.PC);
        ret.Add(new Variable()
        {
            Name = "PC",
            Type = "Program Counter (R15)",
            Value = $"0x{pc:x}"
        });

        if (Options.EnableExtendedControlVariables)
        {
            // Extended: + CPSR, FPEXC, FPSCR, MVFR0-2 

            var cpsr = _engine.Engine.RegRead<uint>(Arm.Register.CPSR);
            ret.Add(new Variable()
            {
                Name = "CPSR",
                Type = "Current Processor State Register",
                Value = $"0x{cpsr:x}",
                VariablesReference = MakeReference(ContainerType.ControlFlags, Arm.Register.CPSR)
            });

            var fpexc = _engine.Engine.RegRead<uint>(Arm.Register.FPEXC);
            ret.Add(new Variable()
            {
                Name = "FPEXC",
                Type = "Floating-Point Exception Control register",
                Value = $"0x{fpexc:x}",
                VariablesReference = MakeReference(ContainerType.ControlFlags, Arm.Register.CPSR)
            });

            var fpscr = _engine.Engine.RegRead<uint>(Arm.Register.FPSCR);
            ret.Add(new Variable()
            {
                Name = "FPSCR",
                Type = "Floating-Point Status and Control Register",
                Value = $"0x{fpscr:x}",
                VariablesReference = MakeReference(ContainerType.ControlFlags, Arm.Register.FPSCR)
            });

            for (var i = 0; i < 3; i++)
            {
                var mvfri = _engine.Engine.RegRead<uint>(Arm.Register.MVFR0 + i);
                ret.Add(new Variable()
                {
                    Name = $"MVFR{i}",
                    Type = $"Media and VFP Feature Register {i}",
                    Value = $"0x{mvfri:x}",
                    VariablesReference = MakeReference(ContainerType.ControlFlags, Arm.Register.MVFR0 + i)
                });
            }
        }
    }


    private void MakeControlFlagsVariables(List<Variable> ret, int regId)
    {
        if (regId == Arm.Register.CPSR || regId == Arm.Register.APSR)
        {
            this.MakeCpsrFlagsVariables(ret, regId);
        }

        // Extended: FPEXC, FPSCR, MVFR0-2 
        if (regId == Arm.Register.FPEXC)
        {
            this.MakeFpexcFlagsVariables(ret);
        }

        if (regId == Arm.Register.FPSCR)
        {
        }

        if (regId == Arm.Register.MVFR0)
        {
        }

        if (regId == Arm.Register.MVFR1)
        {
        }

        if (regId == Arm.Register.MVFR2)
        {
        }
    }

    private readonly string[] _cfFlags = {"N", "Z", "C", "V", "Q", "SSBS", "PAN", "DIT", "GE", "E", "A", "I", "F", "M"};

    private readonly string[] _cfNames =
    {
        "Negative", "Zero", "Carry", "Overflow", "Cumulative saturation",
        "Speculative Store Bypass Safe", "Privileged Access Never", "Data Independent Timing",
        "Greater than or Equal", "Endianness state", "SError interrupt mask", "IRQ mask", "FIQ mask", "Current PE mode"
    };

    private readonly string[] _peModeNames =
        {"User", "FIQ", "IRQ", "Supervisor", "Monitor", "Abort", "Hypervisor", "Undefined", "System"};

    private void MakeCpsrFlagsVariables(List<Variable> ret, int regId)
    {
        // APSR is a subset of CPSR
        var val = _engine.Engine.RegRead<uint>(Arm.Register.CPSR);

        var n = val >> 31;
        var z = (val >> 30) & 0x1;
        var c = (val >> 29) & 0x1;
        var v = (val >> 28) & 0x1;
        var q = (val >> 27) & 0x1;
        var ssbs = (val >> 23) & 0x1;
        var pan = (val >> 22) & 0x1;
        var dit = (val >> 21) & 0x1;
        var ge = (val >> 16) & 0xF;
        var e = (val >> 9) & 0x1;
        var a = (val >> 8) & 0x1;
        var i = (val >> 7) & 0x1;
        var f = (val >> 6) & 0x1;
        var m = val & 0xF;

        uint[] values = {n, z, c, v, q, ssbs, pan, dit, ge, e, a, i, f};

        // N to DIT
        for (var var = 0; var < (regId == Arm.Register.APSR ? 5 : 8); var++)
        {
            ret.Add(new Variable()
            {
                Name = _cfFlags[var],
                Type = _cfNames[var],
                Value = values[var].ToString()
            });
        }

        // GE
        ret.Add(new Variable()
        {
            Name = _cfFlags[8],
            Type = _cfNames[8],
            Value = Convert.ToString(ge, 2)
        });

        if (regId != Arm.Register.APSR)
        {
            // E-F
            for (var var = 9; var < 13; var++)
            {
                ret.Add(new Variable()
                {
                    Name = _cfFlags[var],
                    Type = _cfNames[var],
                    Value = values[var].ToString()
                });
            }

            // M
            ret.Add(new Variable()
            {
                Name = _cfFlags[13],
                Type = _cfNames[13],
                Value = _peModeNames[m]
            });
        }
    }

    private readonly string[] _fpexcFlags =
        {"EX", "EN", "DEX", "TFV", "IDF", "IXF", "UFF", "OFF", "DZF", "IOF"};

    private readonly string[] _fpexcNames =
    {
        "Exception", "Enable access to SIMD/FP", "Defined synchronous exception on FP execution", "Trapped Fault Valid",
        "Input Denormal trapped", "Inexact trapped", "Underflow trapped", "Overflow trapped", "Dividy by Zero trapped",
        "Invalid Operation trapped"
    };

    private void MakeFpexcFlagsVariables(List<Variable> ret)
    {
        var fpexc = _engine.Engine.RegRead<uint>(Arm.Register.FPEXC);
        uint[] values =
        {
            fpexc >> 31, (fpexc >> 30) & 0x1, (fpexc >> 29) & 0x1, (fpexc >> 26) & 0x1, (fpexc >> 7) & 0x1,
            (fpexc >> 4) & 0x1, (fpexc >> 3) & 0x1, (fpexc >> 2) & 0x1, (fpexc >> 1) & 0x1, (fpexc & 0x1)
        };

        for (var i = 0; i < values.Length; i++)
        {
            ret.Add(new Variable()
            {
                Name = _fpexcFlags[i],
                Type = _fpexcNames[i],
                Value = values[i].ToString()
            });
        }
    }

    private void MakeRegistersVariables(List<Variable> ret, ValueFormat? format, int start, int count)
    {
        var end = start + count;
        var isBinary = Options.VariableNumberFormat == VariableNumberFormat.Binary;

        for (var i = start; i < end; i++)
        {
            var regValue = _engine.Engine.RegRead<uint>(Arm.Register.GetRegister(i));
            var value = this.FormatVariable(regValue, format);

            ret.Add(new Variable()
            {
                Name = "R" + i,
                Type = "unsigned int",
                Value = value,
                VariablesReference = isBinary ? 0 : MakeReference(ContainerType.RegisterSubtypes, i)
            });
        }
    }

    private void MakeSubtypeValueVariables<T>(List<Variable> ret, ValueFormat? format, uint baseValue)
        where T : struct
    {
        // TODO: this is not big-endian friendly

        Span<uint> baseSpan = stackalloc uint[1];

        baseSpan[0] = baseValue;

        var values = MemoryMarshal.Cast<uint, T>(baseSpan);

        for (var i = 0; i < values.Length; i++)
        {
            var val = values[i];
            var valS = this.FormatVariable(val, format);

            ret.Add(new Variable()
            {
                Name = $"[{i}]",
                Value = valS
            });
        }
    }

    private void MakeSubtypeVariables(List<Variable> ret, ValueFormat? format, uint baseValue, long baseReference,
        ContainerType targetContainerType)
    {
        ret.Add(new Variable()
        {
            Name = "unsigned bytes",
            Value = string.Empty,
            VariablesReference = MakeReference(targetContainerType, GetTargetAddress(baseReference),
                Subtype.ByteU)
        });

        ret.Add(new Variable()
        {
            Name = "signed bytes",
            Value = string.Empty,
            VariablesReference = MakeReference(targetContainerType, GetTargetAddress(baseReference),
                Subtype.ByteS)
        });

        ret.Add(new Variable()
        {
            Name = "unsigned shorts",
            Value = string.Empty,
            VariablesReference = MakeReference(targetContainerType, GetTargetAddress(baseReference),
                Subtype.ShortU)
        });

        ret.Add(new Variable()
        {
            Name = "signed shorts",
            Value = string.Empty,
            VariablesReference = MakeReference(targetContainerType, GetTargetAddress(baseReference),
                Subtype.ShortS)
        });

        ret.Add(new Variable()
        {
            Name = "unsigned int",
            Value = this.FormatVariable(baseValue, format)
        });

        ret.Add(new Variable()
        {
            Name = "signed int",
            Value = this.FormatVariable(Unsafe.As<uint, int>(ref baseValue), format)
        });

        ret.Add(new Variable()
        {
            Name = "float",
            Value = this.FormatVariable(Unsafe.As<uint, float>(ref baseValue), format)
        });
    }

    private void MakeStackVariables(List<Variable> ret, ValueFormat? format)
    {
        // TODO: support other stack types?

        var stack = this.GetStackSize();

        if (stack == 0)
            return;

        for (var i = 0; i < stack; i += 4)
        {
            var address = (uint) (_engine.StackTopAddress - 4 - i);

            ret.Add(new Variable()
            {
                Name = $"[{i}]",
                Value = string.Empty,
                EvaluateName = $"[SP,{i}]",
                VariablesReference = MakeReference(ContainerType.StackSubtypes, address)
            });
        }
    }

    private static long MakeReference(ContainerType containerType, int regId = 0, Subtype subtype = 0)
    {
        var ret = (((ulong) containerType) & 0xF) | ((((ulong) subtype) & 0xF) << 4) | ((((uint) regId) & 0x1F) << 8);

        return Unsafe.As<ulong, long>(ref ret);
    }

    private static long MakeReference(ContainerType containerType, uint address, Subtype subtype = 0)
    {
        var ret = (((ulong) containerType) & 0xF) | ((((ulong) subtype) & 0xF) << 4) | (((ulong) address) << 8);

        return Unsafe.As<ulong, long>(ref ret);
    }

    private static int GetRegisterId(long variablesReference)
        => unchecked((int) ((((ulong) variablesReference) >> 8) & 0x1F));

    private static uint GetTargetAddress(long variablesReference)
        => unchecked((uint) ((((ulong) variablesReference) >> 8) & 0xFFFFFFFF));

    public IEnumerable<Variable> GetChildVariables(long variablesReference, long? start, long? count,
        ValueFormat? format)
    {
        var containerType = (ContainerType) (variablesReference & 0xF);
        var typeId = (Subtype) ((variablesReference >> 4) & 0xF);
        var regId = GetRegisterId(variablesReference);
        var targetAddress = GetTargetAddress(variablesReference);

        var hex = format?.Hex ?? false;
        var ret = new List<Variable>();

        switch (containerType)
        {
            case ContainerType.Registers:
                this.MakeRegistersVariables(ret, format, (int) (start ?? 0), (int) (count ?? 15));

                break;
            case ContainerType.ControlRegisters:
                this.MakeControlRegistersVariables(ret);

                break;
            case ContainerType.SimdRegisters:
                break;
            case ContainerType.Symbols:
                break;
            case ContainerType.Stack:
                this.MakeStackVariables(ret, format);

                break;
            case ContainerType.RegisterSubtypes:
            {
                var regVal = _engine.Engine.RegRead<uint>(Arm.Register.GetRegister(regId));
                this.MakeSubtypeVariables(ret, format, regVal, variablesReference,
                    ContainerType.RegisterSubtypesValues);

                break;
            }
            case ContainerType.RegisterSubtypesValues:
            {
                var regVal = _engine.Engine.RegRead<uint>(Arm.Register.GetRegister(regId));
                this.MakeSubtypeValueVariables(ret, format, regVal, typeId);

                break;
            }
            case ContainerType.SimdRegisterSubtypes:
                break;
            case ContainerType.SimdRegisterSubtypesValues:
                break;
            case ContainerType.ControlFlags:
                this.MakeControlFlagsVariables(ret, regId);

                break;
            case ContainerType.StackSubtypes:
            {
                var memVal = _engine.Engine.MemReadDirect<uint>(targetAddress);
                this.MakeSubtypeVariables(ret, format, memVal, variablesReference, ContainerType.StackSubtypesValues);

                break;
            }
            case ContainerType.StackSubtypesValues:
            {
                var memVal = _engine.Engine.MemReadDirect<uint>(targetAddress);
                this.MakeSubtypeValueVariables(ret, format, memVal, typeId);

                break;
            }
            default:
                throw new ArgumentOutOfRangeException();
        }

        return ret;
    }

    private void MakeSubtypeValueVariables(List<Variable> ret, ValueFormat? format, uint regVal, Subtype typeId)
    {
        switch (typeId)
        {
            case Subtype.ByteU:
                this.MakeSubtypeValueVariables<byte>(ret, format, regVal);

                break;
            case Subtype.ByteS:
                this.MakeSubtypeValueVariables<sbyte>(ret, format, regVal);

                break;
            case Subtype.ShortU:
                this.MakeSubtypeValueVariables<ushort>(ret, format, regVal);

                break;
            case Subtype.ShortS:
                this.MakeSubtypeValueVariables<short>(ret, format, regVal);

                break;
            default:
                throw new InvalidOperationException();
        }
    }

    public IEnumerable<DisassembledInstruction> Disassemble(string memoryReference, long? byteOffset,
        long? instructionOffset, long instructionCount,
        bool resolveSymbols) =>
        throw new NotImplementedException();

    #region Variable Formatting

    private string FormatVariable(uint variable, ValueFormat? format)
    {
        if ((format?.Hex ?? false) || Options.VariableNumberFormat == VariableNumberFormat.Hex)
            return this.FormatHexSigned(variable);

        if (Options.VariableNumberFormat == VariableNumberFormat.Binary)
            return Convert.ToString(variable, 2);

        return variable.ToString();
    }

    private string FormatVariable<T>(T variable, ValueFormat? format) where T : struct
    {
        if ((format?.Hex ?? false) || Options.VariableNumberFormat == VariableNumberFormat.Hex)
            return this.FormatHexSigned(variable);

        if (Options.VariableNumberFormat == VariableNumberFormat.Binary)
        {
            Span<long> tmp = stackalloc long[1];
            Span<T> tmpTarget = MemoryMarshal.Cast<long, T>(tmp);

            tmp[0] = 0;
            tmpTarget[0] = variable;

            return Convert.ToString(tmp[0], 2);
        }

        return variable.ToString()!;
    }

    private string FormatHexSigned<T>(T variable) where T : struct
    {
        return variable switch
        {
            sbyte x => x < 0 ? $"-0x{(-x):x}" : $"0x{x:x}",
            short x => x < 0 ? $"-0x{(-x):x}" : $"0x{x:x}",
            int x => x < 0 ? $"-0x{(-x):x}" : $"0x{x:x}",
            long x => x < 0 ? $"-0x{(-x):x}" : $"0x{x:x}",
            float x => x.ToString(_clientCulture),
            _ => string.Format(_clientCulture, "0x{0:x}", variable)
        };
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
