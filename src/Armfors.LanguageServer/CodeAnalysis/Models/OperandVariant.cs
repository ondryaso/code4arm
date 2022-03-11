// OperandVariant.cs
// Author: Ondřej Ondryáš

using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum OperandType
{
    Register, // A general-purpose register
    Immediate, // <immX> where X is the bit width of the immediate
    ImmediateDiv4, // <immX> which is a multiple of 4 (so if X=5b, the range is 0 to 2^5*4)
    ImmediateConstant, // #<const>, see "Modified immediate constants" in F1.7.7 (p4363) and J1.2 (p8170)
    ShiftType, // LSL/LSR/ASR/ROR
    Literal, // Anything to match literally (e.g. CSYNC)
    ImmediateAddressing, // any of ImmediateOffset, ImmediatePostIndexed or ImmediatePreIndexed
    ImmediateOffset, // [<Rn> {, #{+/-}<imm>}]
    ImmediatePostIndexed, // [<Rn>], #{+/-}<imm>
    ImmediatePreIndexed, // [<Rn> {, #{+/-}<imm>}]!
    RegisterAddressing, // any of RegisterOffset, RegisterPostIndexed or RegisterPostIndexed
    RegisterOffset, // [<Rn>, #{+/-}<Rm> {, <shift> <imm>}]
    RegisterPostIndexed, // [<Rn>], #{+/-}<Rm> {, <shift> <imm>}
    RegisterPreIndexed, // [<Rn>, #{+/-}<Rm> {, <shift> <imm>}]!
    Label, // <label>
    RRX,
    RegisterList, // <registers_without_pc> (set reg. mask) or <registers>
    RegisterListWithPC, // <registers_with_pc> 
    SimdSingleRegister, // <Sm>
    SimdDoubleRegister, // <Dm>
    SimdQuadRegister, // <Qm>
    SimdSingleRegisterIndexed, // <Sm>[index]
    SimdDoubleRegisterIndexed, // <Dm>[index]
    RegisterWithAlignmentAddressing, // [<Rn>{:<align>}]{!} / [<Rn>{:<align>}], <Rm>; see F1.9.2
    SimdVectorList, // <list>; see F1.9.7
    SimdSingleRegisterList, // <sreglist>
    SimdDoubleRegisterList, // <dreglist>
    SimdSpecialRegister // FPSID, FPSCR, MVFR2, MVFR1, MVFR0, FPEXC (VMRS instr.)
}

public enum OperandTokenType
{
    Immediate,
    Register,
    SimdRegister,
    Label,
    ShiftType
}

public class OperandDescriptor
{
    public Register RegisterMask { get; } = RegisterExtensions.All;

    // If null, all shift types are allowed
    public ShiftType[]? AllowedShiftTypes { get; }

    public int ImmediateSize { get; }

    // Used with Register*Addressing (LDR can shift the offset register, LDRD cannot)
    public bool ShiftAllowed { get; }

    public bool Optional { get; }
    
    public OperandType Type { get; }
    
    public OperandTokenType? SingleTokenType { get; }
    
    public InstructionVariant Mnemonic { get; set; }

    private Regex? _regex = null;
    public Regex Regex => _regex ?? this.MakeRegex();

    public OperandDescriptor(string match, OperandType type, OperandTokenType tokenType, bool optional = false)
    {
        this.Mnemonic = null;

        this.AllowedShiftTypes = null;
        this.ImmediateSize = 0;
        this.ShiftAllowed = false;
        
        this.Optional = optional;
        this.Type = type;
        this.SingleTokenType = tokenType;
        _regex = new Regex(match, RegexOptions.Compiled);
    }
    
    private Regex MakeRegex()
    {
        _regex = new Regex(".*", RegexOptions.Compiled);
        return _regex;
    }
}
