// AnalysedOperand.cs
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

using System.Runtime.InteropServices;
using Code4Arm.LanguageServer.CodeAnalysis.Models.Abstractions;
using OmniSharp.Extensions.LanguageServer.Protocol.Models;

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

using Range = OmniSharp.Extensions.LanguageServer.Protocol.Models.Range;

public enum OperandTokenResult
{
    Valid,
    InvalidRegister,
    InvalidImmediateValue,
    InvalidImmediateConstantValue,
    ImmediateConstantNegative,
    InvalidShiftType,
    InvalidRegisterListEntry,
    RegisterListMustContainPc,
    RegisterListCannotContainPc,
    InvalidAlignment,
    InvalidSpecialOperand,
    UndefinedLabel,
    SyntaxError
}

public enum OperandResult
{
    Valid,
    InvalidTokens,
    UnexpectedOperand,
    MissingOperand,
    SyntaxError
}

[StructLayout(LayoutKind.Explicit)]
public readonly struct AnalysedOperandTokenData
{
    [FieldOffset(0)] public readonly AnalysedLabel? TargetLabel;
    [FieldOffset(8)] public readonly Register Register;
    [FieldOffset(8)] public readonly int Immediate;
    [FieldOffset(8)] public readonly ShiftType ShiftType;

    public AnalysedOperandTokenData(Register register)
    {
        Immediate = default;
        ShiftType = default;
        TargetLabel = default;
        Register = register;
    }

    public AnalysedOperandTokenData(ShiftType shiftType)
    {
        Immediate = default;
        Register = default;
        TargetLabel = default;
        ShiftType = shiftType;
    }

    public AnalysedOperandTokenData(int immediate)
    {
        ShiftType = default;
        Register = default;
        TargetLabel = default;
        Immediate = immediate;
    }
    
    public AnalysedOperandTokenData(AnalysedLabel targetLabel)
    {
        ShiftType = default;
        Register = default;
        Immediate = default;
        TargetLabel = targetLabel;
    }

    public static implicit operator AnalysedOperandTokenData(Register register)
    {
        return new AnalysedOperandTokenData(register);
    }

    public static implicit operator AnalysedOperandTokenData(int immediate)
    {
        return new AnalysedOperandTokenData(immediate);
    }

    public static implicit operator AnalysedOperandTokenData(ShiftType shiftType)
    {
        return new AnalysedOperandTokenData(shiftType);
    }

    public static implicit operator AnalysedOperandTokenData(AnalysedLabel analysedLabel)
    {
        return new AnalysedOperandTokenData(analysedLabel);
    }
}

public record AnalysedOperandToken(OperandTokenDescriptor TokenDescriptor, OperandTokenResult Result, Range Range, string Text,
    AnalysedOperandTokenData Data = default, DiagnosticSeverity Severity = DiagnosticSeverity.Error)
{
    public OperandTokenResult Result { get; set; } = Result;
    public OperandTokenType Type => this.TokenDescriptor.Type;
    public DiagnosticSeverity Severity { get; set; } = Severity;
    public AnalysedOperandTokenData Data { get; set; } = Data;
}

public record AnalysedOperand(int Index, IOperandDescriptor? Descriptor, Range Range, OperandResult Result,
    Range? ErrorRange = null, List<AnalysedOperandToken>? Tokens = null);

public record struct OperandMatchSet();
