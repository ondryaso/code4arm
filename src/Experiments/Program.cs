// Program.cs
// Author: Ondřej Ondryáš

using System.Drawing;
using System.Runtime.InteropServices;
using ELFSharp.ELF;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm;
using UnicornManaged;
using UnicornManaged.Const;

var file = "/home/ondryaso/Projects/bp/testasm/prog20a.elf";
var elfObj = ELFReader.Load<uint>(file);

var codeSegment = elfObj.Segments[0];
var dataSegment = elfObj.Segments[1];

var codeData = codeSegment.GetMemoryContents();
var dataData = dataSegment.GetMemoryContents();

var codeStart = (codeSegment.Address / 4096) * 4096;
var dataStart = (dataSegment.Address / 4096) * 4096;
var trampolineStart = 0xfa000000;

var codeMemorySizeAligned = (((codeData.Length + (codeSegment.Address - codeStart)) / 4096) + 1) * 4096;
var dataMemorySizeAligned = (((dataData.Length + (dataSegment.Address - dataStart)) / 4096) + 1) * 4096;

var textStart = elfObj.Sections[1].LoadAddress;

using var cap = CapstoneDisassembler.CreateArmDisassembler(
    ArmDisassembleMode.LittleEndian | ArmDisassembleMode.V8);

cap.EnableInstructionDetails = true;
var disAsm = cap.Disassemble(codeData[(int)(textStart - codeSegment.Address)..], textStart);

var unicorn = new Unicorn(Common.UC_ARCH_ARM, Common.UC_MODE_ARM | Common.UC_MODE_LITTLE_ENDIAN);

unicorn.MemMap(codeStart, codeMemorySizeAligned, Common.UC_PROT_READ | Common.UC_PROT_EXEC);
unicorn.MemMap(dataStart, dataMemorySizeAligned, Common.UC_PROT_READ | Common.UC_PROT_WRITE);
unicorn.MemMap(trampolineStart, 4096, Common.UC_PROT_READ | Common.UC_PROT_EXEC);

var stackMemoryStart = 0xe0000000;
var stackSize = 2 * 4096;
var stackPtrInitialValue = stackMemoryStart + stackSize;
unicorn.MemMap(stackMemoryStart, stackSize, Common.UC_PROT_READ | Common.UC_PROT_WRITE);
unicorn.RegWrite(Arm.UC_ARM_REG_SP, stackPtrInitialValue);

unicorn.MemWrite(codeSegment.Address, codeData);
unicorn.MemWrite(dataSegment.Address, dataData);
unicorn.MemWrite(trampolineStart, new byte[] { 0x1e, 0xff, 0x2f, 0xe1 });

unicorn.AddEventMemHook(((engine, memType, address, size, _, _) =>
{
    Console.WriteLine($"Unmapped memory op on {address}. R2: {engine.RegRead(Arm.UC_ARM_REG_R2)}");
    return true;
}), Common.UC_HOOK_MEM_UNMAPPED);

unicorn.AddEventMemHook(((engine, memType, address, size, _, _) =>
{
    Console.WriteLine($"Invalid memory op on {address}.");
    return true;
}), Common.UC_HOOK_MEM_INVALID);

unicorn.AddEventMemHook(((engine, memType, address, size, _, _) =>
{
    Console.WriteLine($"Valid memory op on {address}.");
    return true;
}), Common.UC_HOOK_MEM_VALID);

var shouldStop = false;
unicorn.AddInterruptHook((engine, interrupt, _) =>
{
    Console.WriteLine($"Interrupt {interrupt}.");
    engine.EmuStop();
    shouldStop = true;
});

var codeEnd = codeSegment.Address + codeData.Length;

unicorn.AddCodeHook((engine, start, size, _) =>
{
    var pc = engine.RegRead(Arm.UC_ARM_REG_PC);
    Console.WriteLine($"CodeHook: S {start:X}\tPC {pc:X}");
}, 0, long.MaxValue);
/*
unicorn.AddBlockHook((engine, start, size, _) =>
{
    var pc = engine.RegRead(Arm.UC_ARM_REG_PC);
    Console.WriteLine($"BlckHook: S {start:X}\tPC {pc:X}");
}, null, 0, int.MaxValue);
*/
try
{
    long pc = textStart;
    //unicorn.EmuStart(pc, int.MaxValue, 0, 0);


    var i = 0;
    while (!shouldStop)
    {
        var instr = (pc - textStart) / 4;
        if (disAsm.Length > instr)
        {
            Console.WriteLine($"{i++}: #{instr} [{(pc):X}]: {disAsm[instr].Mnemonic} {disAsm[instr].Operand}");
        }
        else
        {
            Console.WriteLine($"{i++}: #? [{pc:X}]");
        }

        unicorn.EmuStart(pc, pc + 4, 0, 0);
        pc = unicorn.RegRead(Arm.UC_ARM_REG_PC) + 4;
    }
}
catch (UnicornEngineException e)
{
    Console.WriteLine(e.Message);
}

unicorn.MemUnmap(codeStart, codeMemorySizeAligned);
unicorn.MemUnmap(dataStart, dataMemorySizeAligned);

unicorn.Close();
unicorn.Dispose();


/*
using var cap = CapstoneDisassembler.CreateArmDisassembler(
    ArmDisassembleMode.LittleEndian | ArmDisassembleMode.V8);

cap.EnableInstructionDetails = true;
//cap.EnableSkipDataMode = true;

var res = cap.Disassemble(code, 0);
foreach (ArmInstruction instruction in res)
{
    var address = instruction.Address;
    ArmInstructionId id = instruction.Id;
    if (!instruction.IsDietModeEnabled)
    {
        // ...
        //
        // An instruction's mnemonic and operand text are only available when Diet Mode is disabled.
        // An exception is thrown otherwise!
        var mnemonic = instruction.Mnemonic;
        var operand = instruction.Operand;
        Console.WriteLine("{0:X}: \t {1} \t {2}", address, mnemonic, operand);
        Console.WriteLine("\t Instruction Id = {0}", id);
    }
    else
    {
        Console.WriteLine("{0:X}:", address);
        Console.WriteLine("\t Id = {0}", id);
    }

    var hexCode = BitConverter.ToString(instruction.Bytes).Replace("-", " ");
    Console.WriteLine("\t Machine Bytes = {0}", hexCode);

    if (instruction.HasDetails)
    {
        Console.WriteLine("\t Condition Code = {0}", instruction.Details.ConditionCode);
        Console.WriteLine("\t Update Flags? = {0}", instruction.Details.UpdateFlags);
        Console.WriteLine("\t Write Back? = {0}", instruction.Details.WriteBack);

        if (!instruction.IsDietModeEnabled)
        {
            // ...
            //
            // Instruction groups are only available when Diet Mode is disabled. An exception is
            // thrown otherwise!
            ArmInstructionGroup[] instructionGroups = instruction.Details.Groups;
            Console.WriteLine("\t # of Instruction Groups: {0}", instructionGroups.Length);
            for (var i = 0; i < instructionGroups.Length; i++)
            {
                // ...
                //
                // A instruction group's name is only available when Diet Mode is disabled. An
                // exception is thrown otherwise! But since we already checked that it is disabled, we
                // don't need to perform another check.
                ArmInstructionGroup instructionGroup = instructionGroups[i];
                Console.Write("\t\t {0}) ", i + 1);
                Console.WriteLine("Id = {0}, Name = {1}", instructionGroup.Id, instructionGroup.Name);
            }

            // ...
            //
            // Explicitly read registers are only available when Diet Mode is disabled. An exception
            // is thrown otherwise!
            ArmRegister[] registers = instruction.Details.ExplicitlyReadRegisters;
            Console.WriteLine("\t # of Explicitly Read Registers: {0}", registers.Length);
            for (var i = 0; i < registers.Length; i++)
            {
                // ...
                //
                // A register's name is only available when Diet Mode is disabled. An exception is
                // thrown otherwise! But since we already checked that it is disabled, we don't need
                // to perform another check.
                ArmRegister register = registers[i];
                Console.Write("\t\t {0}) ", i + 1);
                Console.WriteLine("Id = {0}, Name = {1}", register.Id, register.Name);
            }

            // ...
            //
            // Explicitly modified registers are only available when Diet Mode is disabled. An
            // exception is thrown otherwise!
            registers = instruction.Details.ExplicitlyWrittenRegisters;
            Console.WriteLine("\t # of Explicitly Modified Registers: {0}", registers.Length);
            for (var i = 0; i < registers.Length; i++)
            {
                ArmRegister register = registers[i];
                Console.Write("\t\t {0}) ", i + 1);
                Console.WriteLine("Id = {0}, Name = {1}", register.Id, register.Name);
            }

            // ...
            //
            // Implicitly read registers are only available when Diet Mode is disabled. An exception
            // is thrown otherwise!
            registers = instruction.Details.ImplicitlyReadRegisters;
            Console.WriteLine("\t # of Implicitly Read Registers: {0}", registers.Length);
            for (var i = 0; i < registers.Length; i++)
            {
                ArmRegister register = registers[i];
                Console.Write("\t\t {0}) ", i + 1);
                Console.WriteLine("Id = {0}, Name = {1}", register.Id, register.Name);
            }

            // ...
            //
            // Implicitly modified registers are only available when Diet Mode is disabled. An
            // exception is thrown otherwise!
            registers = instruction.Details.ImplicitlyWrittenRegisters;
            Console.WriteLine("\t # of Implicitly Modified Registers: {0}", registers.Length);
            for (var i = 0; i < registers.Length; i++)
            {
                ArmRegister register = registers[i];
                Console.Write("\t\t {0}) ", i + 1);
                Console.WriteLine("Id = {0}, Name = {1}", register.Id, register.Name);
            }
        }

        // ...
        //
        // An Instruction's operands are always available.
        ArmOperand[] operands = instruction.Details.Operands;
        Console.WriteLine("\t # of Operands: {0}", operands.Length);
        for (var i = 0; i < operands.Length; i++)
        {
            // ...
            //
            // Always check the operand's type before retrieving the associated property. An exception
            // is thrown otherwise!
            ArmOperand operand = operands[i];
            ArmOperandType operandType = operand.Type;
            Console.WriteLine("\t\t {0}) Operand Type: {1}", i + 1, operandType);

            if (operand.Type == ArmOperandType.Immediate)
            {
                var immediate = operand.Immediate;
                Console.WriteLine("\t\t\t Immediate Value = {0:X}", immediate);
            }
            else if (operand.Type == ArmOperandType.Memory)
            {
                ArmMemoryOperandValue memory = operand.Memory;
                Console.WriteLine("\t\t\t Memory Value:");

                // ...
                //
                // For a memory operand, an irrelevant base register will be a null reference!
                ArmRegister @base = memory.Base;
                if (@base != null)
                {
                    if (!@base.IsDietModeEnabled)
                    {
                        // ...
                        //
                        // A register's name is only available when Diet Mode is disabled. An
                        // exception is thrown otherwise!
                        ArmRegisterId baseId = @base.Id;
                        var baseName = @base.Name;
                        Console.WriteLine("\t\t\t\t Base: Id = {0}, Name = {1}", baseId, baseName);
                    }
                    else
                    {
                        // ...
                        //
                        // A register's unique identifier is always available.
                        Console.WriteLine("\t\t\t\t Base: Id = {0}", @base.Id);
                    }
                }

                var displacement = memory.Displacement;
                Console.WriteLine("\t\t\t\t Displacement Value = {0}", displacement);

                // ...
                //
                // For a memory operand, an irrelevant index register will be a null reference!
                ArmRegister index = memory.Index;
                if (index != null)
                {
                    if (!index.IsDietModeEnabled)
                    {
                        ArmRegisterId indexId = index.Id;
                        var indexName = index.Name;
                        Console.WriteLine("\t\t\t\t Index: Id = {0}, Name = {1}", indexId, indexName);
                    }
                    else
                    {
                        Console.WriteLine("\t\t\t\t Index: Id = {0}", index.Id);
                    }
                }
            }
            else if (operand.Type == ArmOperandType.SystemRegister)
            {
                ArmSystemRegister mrsRegister = operand.SystemRegister;
                Console.WriteLine("\t\t\t System Register = {0}", mrsRegister);
            }
            else if (operand.Type == ArmOperandType.Register)
            {
                ArmRegister register = operand.Register;
                if (!register.IsDietModeEnabled)
                {
                    // ...
                    //
                    // A register's name is only available when Diet Mode is disabled. An exception is
                    // thrown otherwise!
                    ArmRegisterId registerId = register.Id;
                    var name = register.Name;
                    Console.WriteLine("\t\t\t Register: Id = {0}, Name = {1}", registerId, name);
                }
                else
                {
                    // ...
                    //
                    // A register's unique identifier is always available.
                    Console.WriteLine("\t\t\t Register: Id = {0}", register.Id);
                }
            }

            if (!operand.IsDietModeEnabled)
            {
                // ...
                //
                // An operand's access type is only available when Diet Mode is disabled. An exception
                // is thrown otherwise!
                OperandAccessType accessType = operand.AccessType;
                Console.WriteLine("\t\t\t Access Type = {0}", accessType);
            }

            ArmShiftOperation shiftOperation = operand.ShiftOperation;
            Console.WriteLine("\t\t\t Shift Operation: {0}", shiftOperation);
            if (shiftOperation != ArmShiftOperation.Invalid)
            {
                // ...
                //
                // An operand's shift value is only available if the shift operation is not invalid.
                // An exception is thrown otherwise!
                var shiftValue = operand.ShiftValue;
                Console.WriteLine("\t\t\t\t Shift Value = {0}", shiftValue);
            }

            var vectorIndex = operand.VectorIndex;
            Console.WriteLine("\t\t\t Vector Index = {0}", vectorIndex);
        }
    }

    Console.WriteLine();
    Console.ReadLine();
}
*/
