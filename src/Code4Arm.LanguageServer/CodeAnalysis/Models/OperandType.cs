// OperandType.cs
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

using System.Diagnostics.CodeAnalysis;

namespace Code4Arm.LanguageServer.CodeAnalysis.Models;

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