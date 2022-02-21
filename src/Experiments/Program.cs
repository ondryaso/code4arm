// Program.cs
// Author: Ondřej Ondryáš

using ELFSharp.ELF;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm;

var file = "/home/ondryaso/Projects/bp/testasm/abc";
var elfObj = ELFReader.Load<uint>(file);
var elfLd = ELFReader.Load<uint>(file + "2");

using var cap = CapstoneDisassembler.CreateArmDisassembler(
    ArmDisassembleMode.LittleEndian | ArmDisassembleMode.V8);

cap.EnableInstructionDetails = true;
//cap.EnableSkipDataMode = true;

var code = elfObj.Sections[1].GetContents();
var c2 = elfLd.Sections[1].GetContents();
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
