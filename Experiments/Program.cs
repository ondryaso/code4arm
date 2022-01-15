using System.IO.MemoryMappedFiles;
using Keystone;
using UnicornManaged;
using UnicornManaged.Const;

const string code = @"
mov r0, #3
mov r1, #15
mov r2, #1
pow:
    mul r2, r2, r0
    subs r1, r1, #1
    bne pow
";

using var keystone = new Engine(Architecture.ARM, Mode.ARM) { ThrowOnError = true };
/*
keystone.ResolveSymbol += (string symbol, ref ulong value) =>
{
    if (symbol == "_printf")
    {
        value = int.MaxValue;
        return true;
    }

    if (symbol == "value")
    {
        value = 0xF0;
        return true;
    }

    return false;
};*/

Console.WriteLine("--- Assembling ---");
var encodedData = keystone.Assemble(code, 0);

Console.WriteLine("Total statements: " + encodedData.StatementCount);
Console.WriteLine($"Total code size: {encodedData.Buffer.Length} B");

var i = 0;
foreach (var b in encodedData.Buffer)
{
    Console.Write(b.ToString("x2") + " ");
    if (i++ == 16)
    {
        Console.WriteLine();
        i = 0;
    }
}

Console.WriteLine("\n\n--- Execution ---");

using var unicorn = new Unicorn(Common.UC_ARCH_ARM, Common.UC_MODE_ARM);

unicorn.MemMap(0, 4 * 1024, Common.UC_PROT_ALL);
unicorn.MemWrite(0, encodedData.Buffer);
unicorn.MemWrite(0xF0, new byte[] { 127, 255, 0, 0 });
unicorn.RegWrite(Arm.UC_ARM_REG_SP, 512);

unicorn.AddCodeHook((engine, address, size, data) =>
    {
        //Console.WriteLine($"Address: {address:X}\tSize: {size}\tThread: {Environment.CurrentManagedThreadId}");
        Console.WriteLine($"{address:X2} | R0: {unicorn.RegRead(Arm.UC_ARM_REG_R0)}, R1: {unicorn.RegRead(Arm.UC_ARM_REG_R1)}, R2: {unicorn.RegRead(Arm.UC_ARM_REG_R2):X}");
    },
    0, encodedData.Buffer.Length);


unicorn.AddInterruptHook(((unicorn1, i1, o) => unicorn1.EmuStop()));
unicorn.AddBlockHook(((unicorn1, l, i1, o) => Console.WriteLine("Block")), null, 0, encodedData.Buffer.Length);
unicorn.AddEventMemHook(((unicorn1, i1, l, i2, l1, o) =>
{
    Console.WriteLine("Event");
    return true;
}), Common.UC_HOOK_MEM_FETCH);

unicorn.EmuStart(0, encodedData.Buffer.Length, 0, 0);


Console.WriteLine($"R0: {unicorn.RegRead(Arm.UC_ARM_REG_R0)}, R1: {unicorn.RegRead(Arm.UC_ARM_REG_R1)}, R2: {unicorn.RegRead(Arm.UC_ARM_REG_R2)}");
