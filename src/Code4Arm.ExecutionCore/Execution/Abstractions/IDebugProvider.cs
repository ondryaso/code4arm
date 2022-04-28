// IDebugProvider.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

public interface IDebugProvider
{
    InitializeResponse Initialize(InitializeRequestArguments clientData);

    IEnumerable<GotoTarget> GetGotoTargets(Source source, long line, long? column);
    SetVariableResponse SetVariable(long containerId, string variableName, string value, ValueFormat? format);
    SourceResponse GetSource(long sourceReference);
    SourceResponse GetSource(Source source);
    DataBreakpointInfoResponse GetDataBreakpointInfo(long containerId, string variableName);
    DataBreakpointInfoResponse GetDataBreakpointInfo(string expression);
    EvaluateResponse EvaluateExpression(string expression, EvaluateArgumentsContext? context, ValueFormat? format);
    ExceptionInfoResponse GetLastExceptionInfo();
    StackTraceResponse MakeStackTrace();
    ScopesResponse MakeVariableScopes();
    IEnumerable<BreakpointLocation> GetBreakpointLocations(Source source, int line, int? endLine);
    IEnumerable<ExceptionBreakpointsFilter> GetExceptionBreakpointFilters();
    ReadMemoryResponse ReadMemory(string memoryReference, long count, long? offset);
    WriteMemoryResponse WriteMemory(string memoryReference, bool allowPartial, long? offset, string dataEncoded);

    IEnumerable<Variable> GetChildVariables(long containerId, string parentVariableName, long? start, long? count,
        ValueFormat? format);

    IEnumerable<Variable> GetChildVariables(long variablesReference, long? start, long? count, ValueFormat? format);

    IEnumerable<DisassembledInstruction> Disassemble(string memoryReference, long? byteOffset, long? instructionOffset,
        long instructionCount, bool resolveSymbols);

    #region Wrappers over DP's arguments objects

    IEnumerable<GotoTarget> GetGotoTargets(GotoTargetsArguments arguments)
        => this.GetGotoTargets(arguments.Source, arguments.Line, arguments.Column);

    DataBreakpointInfoResponse GetDataBreakpointInfo(DataBreakpointInfoArguments arguments)
        => arguments.VariablesReference.HasValue
            ? this.GetDataBreakpointInfo(arguments.VariablesReference.Value, arguments.Name)
            : this.GetDataBreakpointInfo(arguments.Name);

    SetVariableResponse SetVariable(SetVariableArguments arguments)
        => this.SetVariable(arguments.VariablesReference, arguments.Name, arguments.Value, arguments.Format);

    SourceResponse GetSource(SourceArguments arguments)
        => arguments.Source == null ? this.GetSource(arguments.SourceReference) : this.GetSource(arguments.Source);

    EvaluateResponse EvaluateExpression(EvaluateArguments arguments)
        => this.EvaluateExpression(arguments.Expression, arguments.Context, arguments.Format);

    IEnumerable<BreakpointLocation> GetBreakpointLocations(BreakpointLocationsArguments arguments)
        => this.GetBreakpointLocations(arguments.Source, arguments.Line, arguments.EndLine);

    IEnumerable<DisassembledInstruction> Disassemble(DisassembleArguments arguments)
        => this.Disassemble(arguments.MemoryReference, arguments.Offset, arguments.InstructionOffset,
            arguments.InstructionCount, arguments.ResolveSymbols);

    ReadMemoryResponse ReadMemory(ReadMemoryArguments arguments)
        => this.ReadMemory(arguments.MemoryReference, arguments.Count, arguments.Offset);

    WriteMemoryResponse WriteMemory(WriteMemoryArguments arguments)
        => this.WriteMemory(arguments.MemoryReference, arguments.AllowPartial, arguments.Offset, arguments.Data);

    IEnumerable<Variable> GetChildVariables(VariablesArguments arguments)
        => this.GetChildVariables(arguments.VariablesReference, arguments.Start, arguments.Count, arguments.Format);

    #endregion
}
