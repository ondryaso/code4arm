// OperandType.cs
// Author: Ondřej Ondryáš

using System.Diagnostics.CodeAnalysis;

namespace Armfors.LanguageServer.CodeAnalysis.Models;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum OperandType
{
    Register, // A general-purpose register
    Immediate, // <immX> where X is the bit width of the immediate
    ImmediateDiv4, // <immX> which is a multiple of 4 (so if X=5b, the range is 0 to 2^5*4)
    ImmediateConstant, // #<const>, see "Modified immediate constants" in F1.7.7 (p4363) and J1.2 (p8170)
    Shift, // LSL/LSR/ASR/ROR #<amount>
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