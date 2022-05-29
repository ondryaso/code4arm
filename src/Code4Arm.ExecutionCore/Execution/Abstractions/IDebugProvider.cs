// IDebugProvider.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public interface IDebugProvider
{
    DebuggerOptions Options { get; set; }
    InitializeRequestArguments? ClientInfo { get; }

    InitializeResponse Initialize(InitializeRequestArguments clientData);

    IEnumerable<GotoTarget> GetGotoTargets(Source source, int line, int? column);
    SetExpressionResponse SetExpression(string expression, string value, ValueFormat? format);

    Task<SetVariableResponse> SetVariable(long parentVariablesReference, string variableName, string value,
        ValueFormat? format);

    DataBreakpointInfoResponse GetDataBreakpointInfo(long parentVariablesReference, string variableName);
    DataBreakpointInfoResponse GetDataBreakpointInfo(string expression);
    EvaluateResponse EvaluateExpression(string expression, EvaluateArgumentsContext? context, ValueFormat? format);
    ExceptionInfoResponse GetLastExceptionInfo();
    Task<StackTraceResponse> MakeStackTrace();
    ScopesResponse MakeVariableScopes();
    IEnumerable<BreakpointLocation> GetBreakpointLocations(Source source, int line, int? endLine);
    ReadMemoryResponse ReadMemory(string memoryReference, long count, long? offset);
    WriteMemoryResponse WriteMemory(string memoryReference, bool allowPartial, long? offset, string dataEncoded);

    IEnumerable<Variable> GetChildVariables(long parentVariablesReference, int? start, int? count, ValueFormat? format);

    Task<IEnumerable<DisassembledInstruction>> Disassemble(string memoryReference, long? byteOffset,
        long? instructionOffset,
        long instructionCount, bool resolveSymbols);

    #region Wrappers over DP's arguments objects

    IEnumerable<GotoTarget> GetGotoTargets(GotoTargetsArguments arguments)
        => this.GetGotoTargets(arguments.Source, (int)arguments.Line, (int?)arguments.Column);

    DataBreakpointInfoResponse GetDataBreakpointInfo(DataBreakpointInfoArguments arguments)
        => arguments.VariablesReference.HasValue
            ? this.GetDataBreakpointInfo(arguments.VariablesReference.Value, arguments.Name)
            : this.GetDataBreakpointInfo(arguments.Name);

    SetExpressionResponse SetExpression(SetExpressionArguments arguments)
        => this.SetExpression(arguments.Expression, arguments.Value, arguments.Format);

    Task<SetVariableResponse> SetVariable(SetVariableArguments arguments)
        => this.SetVariable(arguments.VariablesReference, arguments.Name, arguments.Value, arguments.Format);

    EvaluateResponse EvaluateExpression(EvaluateArguments arguments)
        => this.EvaluateExpression(arguments.Expression, arguments.Context, arguments.Format);

    IEnumerable<BreakpointLocation> GetBreakpointLocations(BreakpointLocationsArguments arguments)
        => this.GetBreakpointLocations(arguments.Source, arguments.Line, arguments.EndLine);

    Task<IEnumerable<DisassembledInstruction>> Disassemble(DisassembleArguments arguments)
        => this.Disassemble(arguments.MemoryReference, arguments.Offset, arguments.InstructionOffset,
            arguments.InstructionCount, arguments.ResolveSymbols);

    ReadMemoryResponse ReadMemory(ReadMemoryArguments arguments)
        => this.ReadMemory(arguments.MemoryReference, arguments.Count, arguments.Offset);

    WriteMemoryResponse WriteMemory(WriteMemoryArguments arguments)
        => this.WriteMemory(arguments.MemoryReference, arguments.AllowPartial, arguments.Offset, arguments.Data);

    IEnumerable<Variable> GetChildVariables(VariablesArguments arguments)
        => this.GetChildVariables(arguments.VariablesReference, (int?)arguments.Start, (int?)arguments.Count,
            arguments.Format);

    #endregion
}
