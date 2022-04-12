// Program.cs
// Author: Ondřej Ondryáš

using System.Drawing;
using System.Runtime.InteropServices;
using ELFSharp.ELF;
using ELFSharp.ELF.Sections;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm;
using UnicornManaged;
using UnicornManaged.Const;

var file = "/home/ondryaso/Projects/bp/testasm/prog20a.elf";
var elfObj = ELFReader.Load<uint>(file);

var symbolTable = elfObj.Sections.FirstOrDefault(s => s.Type == SectionType.SymbolTable) as SymbolTable<uint>;
var symbols = symbolTable!.Entries.OrderBy(e => e.Value);
Console.WriteLine("Num\tValue\t\tSecIdx\tSecName\tName");
var m = 0;
foreach (var symbol in symbols)
{
    Console.WriteLine($"{m++}\t{symbol.Value:x8}\t{symbol.PointedSectionIndex}\t{symbol.PointedSection?.Name ?? "-"}\t{symbol.Name}");
}

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
