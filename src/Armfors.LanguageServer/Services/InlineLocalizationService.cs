// InlineLocalizationService.cs
// Author: Ondřej Ondryáš

using Armfors.LanguageServer.CodeAnalysis.Models;
using Armfors.LanguageServer.Services.Abstractions;
using L = Armfors.LanguageServer.Services.Abstractions.ILocalizationService;

namespace Armfors.LanguageServer.Services;

public class InlineLocalizationService : ILocalizationService
{
    private const string CompLabel = L.CompletionLabelTag;
    private const string CompLabelSimd = L.CompletionLabelSimdTag;
    private const string CompDescription = L.CompletionDescriptionTag;
    private const string CompDescriptionSimd = L.CompletionDescriptionSimdTag;
    private const string CompDocumentation = L.CompletionDocumentationTag;
    private const string CompDocumentationSimd = L.CompletionDocumentationSimdTag;

    private readonly Dictionary<string, string?> _values = new()
    {
        { L.GetEnumEntryIdentifier(ConditionCode.AL, CompLabel), "-AL (Always)" },
        { L.GetEnumEntryIdentifier(ConditionCode.CC, CompLabel), "-CC (Carry clear)" },
        { L.GetEnumEntryIdentifier(ConditionCode.CS, CompLabel), "-CS (Carry set)" },
        { L.GetEnumEntryIdentifier(ConditionCode.EQ, CompLabel), "-EQ (Equal)" },
        { L.GetEnumEntryIdentifier(ConditionCode.GE, CompLabel), "-GE (Signed >=)" },
        { L.GetEnumEntryIdentifier(ConditionCode.GT, CompLabel), "-GT (Signed >)" },
        { L.GetEnumEntryIdentifier(ConditionCode.HI, CompLabel), "-HI (Unsigned >)" },
        { L.GetEnumEntryIdentifier(ConditionCode.HS, CompLabel), "-HS (Unsigned >=)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LE, CompLabel), "-LE (Signed <=)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LO, CompLabel), "-LO (Unsigned <)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LS, CompLabel), "-LS (Unsigned <=)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LT, CompLabel), "-LT (Signed <)" },
        { L.GetEnumEntryIdentifier(ConditionCode.MI, CompLabel), "-MI (Negative)" },
        { L.GetEnumEntryIdentifier(ConditionCode.NE, CompLabel), "-NE (Not equal)" },
        { L.GetEnumEntryIdentifier(ConditionCode.PL, CompLabel), "-PL (Positive/zero)" },
        { L.GetEnumEntryIdentifier(ConditionCode.VC, CompLabel), "-VC (Overflow clear)" },
        { L.GetEnumEntryIdentifier(ConditionCode.VS, CompLabel), "-VS (Overflow set)" },

        { L.GetEnumEntryIdentifier(ConditionCode.AL, CompDescription), "Always" },
        { L.GetEnumEntryIdentifier(ConditionCode.CC, CompDescription), "Carry clear / Unsigned < (C == 0)" },
        { L.GetEnumEntryIdentifier(ConditionCode.CS, CompDescription), "Carry set / Unsigned >= (C == 1)" },
        { L.GetEnumEntryIdentifier(ConditionCode.EQ, CompDescription), "Equal (Z == 1)" },
        { L.GetEnumEntryIdentifier(ConditionCode.GE, CompDescription), "Signed >= (N == V)" },
        { L.GetEnumEntryIdentifier(ConditionCode.GT, CompDescription), "Signed > (Z == 0 & N == V)" },
        { L.GetEnumEntryIdentifier(ConditionCode.HI, CompDescription), "Unsigned > (C == 1 & Z == 0)" },
        { L.GetEnumEntryIdentifier(ConditionCode.HS, CompDescription), "Unsigned >= / Carry set (C == 1)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LE, CompDescription), "Signed <= (Z == 1 | N != V)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LO, CompDescription), "Unsigned < / Carry clear (C == 0)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LS, CompDescription), "Unsigned <= (C == 0 | Z == 1)" },
        { L.GetEnumEntryIdentifier(ConditionCode.LT, CompDescription), "Signed < (N != V)" },
        { L.GetEnumEntryIdentifier(ConditionCode.MI, CompDescription), "Negative (N == 1)" },
        { L.GetEnumEntryIdentifier(ConditionCode.NE, CompDescription), "Not equal (Z == 0)" },
        { L.GetEnumEntryIdentifier(ConditionCode.PL, CompDescription), "Positive/zero (N == 0)" },
        { L.GetEnumEntryIdentifier(ConditionCode.VC, CompDescription), "Overflow clear (V == 0)" },
        { L.GetEnumEntryIdentifier(ConditionCode.VS, CompDescription), "Overflow set (V == 0)" },

        { L.GetEnumEntryIdentifier(VectorDataType.Any8, CompLabel), ".8 (any 8b element)" },
        { L.GetEnumEntryIdentifier(VectorDataType.Any16, CompLabel), ".16 (any 16b element)" },
        { L.GetEnumEntryIdentifier(VectorDataType.Any32, CompLabel), ".32 (any 32b element)" },
        { L.GetEnumEntryIdentifier(VectorDataType.Any64, CompLabel), ".64 (any 64b element)" },
        { L.GetEnumEntryIdentifier(VectorDataType.I8, CompLabel), ".I8 (sign./unsig. byte)" },
        { L.GetEnumEntryIdentifier(VectorDataType.I16, CompLabel), ".I16 (sign./unsig. halfword)" },
        { L.GetEnumEntryIdentifier(VectorDataType.I32, CompLabel), ".I32 (sign./unsig. word)" },
        { L.GetEnumEntryIdentifier(VectorDataType.I64, CompLabel), ".I64 (sign./unsig. doubleword)" },
        { L.GetEnumEntryIdentifier(VectorDataType.S8, CompLabel), ".S8 (signed byte)" },
        { L.GetEnumEntryIdentifier(VectorDataType.S16, CompLabel), ".S16 (signed halfword)" },
        { L.GetEnumEntryIdentifier(VectorDataType.S32, CompLabel), ".S32 (signed word)" },
        { L.GetEnumEntryIdentifier(VectorDataType.S64, CompLabel), ".S64 (signed doubleword)" },
        { L.GetEnumEntryIdentifier(VectorDataType.U8, CompLabel), ".U8 (unsigned byte)" },
        { L.GetEnumEntryIdentifier(VectorDataType.U16, CompLabel), ".U16 (unsigned halfword)" },
        { L.GetEnumEntryIdentifier(VectorDataType.U32, CompLabel), ".U32 (unsigned word)" },
        { L.GetEnumEntryIdentifier(VectorDataType.U64, CompLabel), ".U64 (unsigned doubleword)" },
        { L.GetEnumEntryIdentifier(VectorDataType.P8, CompLabel), ".P8 (polynomial over {0,1} of degree <8)" },
        { L.GetEnumEntryIdentifier(VectorDataType.P16, CompLabel), ".P16 (polynomial over {0,1} of degree <16)" },
        { L.GetEnumEntryIdentifier(VectorDataType.F16, CompLabel), ".F16 (half-precision float)" },
        { L.GetEnumEntryIdentifier(VectorDataType.F32, CompLabel), ".F32 (single float)" },
        { L.GetEnumEntryIdentifier(VectorDataType.F64, CompLabel), ".F64 (double float)" },
        
        { L.GetEnumEntryIdentifier(Register.R0, CompLabel), "R0" },
        { L.GetEnumEntryIdentifier(Register.R1, CompLabel), "R1" },
        { L.GetEnumEntryIdentifier(Register.R2, CompLabel), "R2" },
        { L.GetEnumEntryIdentifier(Register.R3, CompLabel), "R3" },
        { L.GetEnumEntryIdentifier(Register.R4, CompLabel), "R4" },
        { L.GetEnumEntryIdentifier(Register.R5, CompLabel), "R5" },
        { L.GetEnumEntryIdentifier(Register.R6, CompLabel), "R6" },
        { L.GetEnumEntryIdentifier(Register.R7, CompLabel), "R7" },
        { L.GetEnumEntryIdentifier(Register.R8, CompLabel), "R8" },
        { L.GetEnumEntryIdentifier(Register.R9, CompLabel), "R9" },
        { L.GetEnumEntryIdentifier(Register.R10, CompLabel), "R10" },
        { L.GetEnumEntryIdentifier(Register.R11, CompLabel), "R11" },
        { L.GetEnumEntryIdentifier(Register.R12, CompLabel), "R12" },
        { L.GetEnumEntryIdentifier(Register.SP, CompLabel), "SP (R13)" },
        { L.GetEnumEntryIdentifier(Register.LR, CompLabel), "LR (R14)" },
        { L.GetEnumEntryIdentifier(Register.PC, CompLabel), "PC (R15)" },
        
        { L.GetEnumEntryIdentifier(ShiftType.ASR, CompLabel), "ASR (arithm. shift right)" },
        { L.GetEnumEntryIdentifier(ShiftType.LSL, CompLabel), "LSL (logical shift left)" },
        { L.GetEnumEntryIdentifier(ShiftType.LSR, CompLabel), "LSR (logical shift right)" },
        { L.GetEnumEntryIdentifier(ShiftType.ROR, CompLabel), "ROR (rotate right)" },
        
        { L.GetEnumEntryIdentifier(ShiftType.ASR, CompDescription), "Shifts right, keeps sign" },
        { L.GetEnumEntryIdentifier(ShiftType.LSL, CompDescription), "Shifts left" },
        { L.GetEnumEntryIdentifier(ShiftType.LSR, CompDescription), "Shifts right, fills with 0s" },
        { L.GetEnumEntryIdentifier(ShiftType.ROR, CompDescription), "Rotates right" },
        
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
