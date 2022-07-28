// InlineLocalizationService.cs
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

using Code4Arm.LanguageServer.CodeAnalysis.Models;
using Code4Arm.LanguageServer.Services.Abstractions;
using L = Code4Arm.LanguageServer.Services.Abstractions.ILocalizationService;

namespace Code4Arm.LanguageServer.Services;

public class InlineLocalizationService : ILocalizationService
{
    private const string CompLabel = ILocalizationService.CompletionLabelTag;
    private const string CompLabelSimd = ILocalizationService.CompletionLabelSimdTag;
    private const string CompDescription = ILocalizationService.CompletionDescriptionTag;
    private const string CompDescriptionSimd = ILocalizationService.CompletionDescriptionSimdTag;
    private const string CompDocumentation = ILocalizationService.CompletionDocumentationTag;
    private const string CompDocumentationSimd = ILocalizationService.CompletionDocumentationSimdTag;

    private readonly Dictionary<string, string?> _values = new()
    {
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.AL, CompLabel), "-AL (Always)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.CC, CompLabel), "-CC (Carry clear)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.CS, CompLabel), "-CS (Carry set)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.EQ, CompLabel), "-EQ (Equal)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.GE, CompLabel), "-GE (Signed >=)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.GT, CompLabel), "-GT (Signed >)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.HI, CompLabel), "-HI (Unsigned >)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.HS, CompLabel), "-HS (Unsigned >=)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.LE, CompLabel), "-LE (Signed <=)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.LO, CompLabel), "-LO (Unsigned <)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.LS, CompLabel), "-LS (Unsigned <=)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.LT, CompLabel), "-LT (Signed <)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.MI, CompLabel), "-MI (Negative)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.NE, CompLabel), "-NE (Not equal)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.PL, CompLabel), "-PL (Positive/zero)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.VC, CompLabel), "-VC (Overflow clear)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.VS, CompLabel), "-VS (Overflow set)" },

        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.AL, CompDescription), "Always" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.CC, CompDescription), "Carry clear / Unsigned < (C == 0)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.CS, CompDescription), "Carry set / Unsigned >= (C == 1)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.EQ, CompDescription), "Equal (Z == 1)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.GE, CompDescription), "Signed >= (N == V)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.GT, CompDescription), "Signed > (Z == 0 & N == V)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.HI, CompDescription), "Unsigned > (C == 1 & Z == 0)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.HS, CompDescription), "Unsigned >= / Carry set (C == 1)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.LE, CompDescription), "Signed <= (Z == 1 | N != V)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.LO, CompDescription), "Unsigned < / Carry clear (C == 0)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.LS, CompDescription), "Unsigned <= (C == 0 | Z == 1)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.LT, CompDescription), "Signed < (N != V)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.MI, CompDescription), "Negative (N == 1)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.NE, CompDescription), "Not equal (Z == 0)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.PL, CompDescription), "Positive/zero (N == 0)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.VC, CompDescription), "Overflow clear (V == 0)" },
        { ILocalizationService.GetEnumEntryIdentifier(ConditionCode.VS, CompDescription), "Overflow set (V == 0)" },

        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.Any8, CompLabel), ".8 (any 8b element)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.Any16, CompLabel), ".16 (any 16b element)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.Any32, CompLabel), ".32 (any 32b element)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.Any64, CompLabel), ".64 (any 64b element)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.I8, CompLabel), ".I8 (sign./unsig. byte)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.I16, CompLabel), ".I16 (sign./unsig. halfword)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.I32, CompLabel), ".I32 (sign./unsig. word)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.I64, CompLabel), ".I64 (sign./unsig. doubleword)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.S8, CompLabel), ".S8 (signed byte)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.S16, CompLabel), ".S16 (signed halfword)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.S32, CompLabel), ".S32 (signed word)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.S64, CompLabel), ".S64 (signed doubleword)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.U8, CompLabel), ".U8 (unsigned byte)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.U16, CompLabel), ".U16 (unsigned halfword)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.U32, CompLabel), ".U32 (unsigned word)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.U64, CompLabel), ".U64 (unsigned doubleword)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.P8, CompLabel), ".P8 (polynomial over {0,1} of degree <8)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.P16, CompLabel), ".P16 (polynomial over {0,1} of degree <16)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.F16, CompLabel), ".F16 (half-precision float)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.F32, CompLabel), ".F32 (single float)" },
        { ILocalizationService.GetEnumEntryIdentifier(VectorDataType.F64, CompLabel), ".F64 (double float)" },
        
        { ILocalizationService.GetEnumEntryIdentifier(Register.R0, CompLabel), "R0" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.R1, CompLabel), "R1" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.R2, CompLabel), "R2" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.R3, CompLabel), "R3" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.R4, CompLabel), "R4" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.R5, CompLabel), "R5" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.R6, CompLabel), "R6" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.R7, CompLabel), "R7" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.R8, CompLabel), "R8" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.R9, CompLabel), "R9" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.R10, CompLabel), "R10" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.R11, CompLabel), "R11" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.R12, CompLabel), "R12" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.SP, CompLabel), "SP (R13)" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.LR, CompLabel), "LR (R14)" },
        { ILocalizationService.GetEnumEntryIdentifier(Register.PC, CompLabel), "PC (R15)" },
        
        { ILocalizationService.GetEnumEntryIdentifier(ShiftType.ASR, CompLabel), "ASR (arithm. shift right)" },
        { ILocalizationService.GetEnumEntryIdentifier(ShiftType.LSL, CompLabel), "LSL (logical shift left)" },
        { ILocalizationService.GetEnumEntryIdentifier(ShiftType.LSR, CompLabel), "LSR (logical shift right)" },
        { ILocalizationService.GetEnumEntryIdentifier(ShiftType.ROR, CompLabel), "ROR (rotate right)" },
        
        { ILocalizationService.GetEnumEntryIdentifier(ShiftType.ASR, CompDescription), "Shifts right, keeps sign" },
        { ILocalizationService.GetEnumEntryIdentifier(ShiftType.LSL, CompDescription), "Shifts left" },
        { ILocalizationService.GetEnumEntryIdentifier(ShiftType.LSR, CompDescription), "Shifts right, fills with 0s" },
        { ILocalizationService.GetEnumEntryIdentifier(ShiftType.ROR, CompDescription), "Rotates right" },
        
        {$"Label.{CompDescription}", "label"},
        {$"FunctionSymbol.{CompDescription}", "function symbol"},
        
        { $"Set flags.{CompLabel}", "-S (Set flags)" },
        { $"Set flags.{CompDescription}", "Set flags" }
    };

    public string this[string entry] => _values.TryGetValue(entry, out var val) ? (val ?? string.Empty) : string.Empty;

    public string this[string entry, int count] => this[entry];

    public bool HasValue(string entry) => _values.ContainsKey(entry);
    public bool TryGetValue(string entry, out string? value) => _values.TryGetValue(entry, out value);
}
