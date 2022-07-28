// IDebugProvider.cs
// 
// This file is a part of project Code4Arm, created for a thesis "Simulation of an Arm processor for the education
// of programming in assembler".
// Copyright (c) 2022 Ondřej Ondryáš <xondry02@stud.fit.vutbr.cz>
// 
// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License along with this program.
// If not, see <https://www.gnu.org/licenses/>.

using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;

namespace Code4Arm.ExecutionCore.Execution.Abstractions;

/// <summary>
/// Exposes functions of the Debug Adapter Protocol used to inspect the state of the emulated program.
/// For reference, see <a href="https://microsoft.github.io/debug-adapter-protocol/specification">the DAP specification</a>.
/// The debug provider's behaviour is configured using the settable <see cref="DebuggerOptions"/> property.
/// </summary>
public interface IDebugProvider
{
    DebuggerOptions Options { get; set; }
    
    /// <summary>
    /// The <see cref="InitializeRequestArguments"/> object received from the client after debugging has started.
    /// Contains the current client's capabilities. 
    /// </summary>
    InitializeRequestArguments? ClientInfo { get; }

    /// <summary>
    /// Handles the DAP 'Initialize' request from the client. Must be called before any other method of the debug provider.
    /// </summary>
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
