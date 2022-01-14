using Keystone;
using UnicornManaged;
using UnicornManaged.Const;

const string code = @"
start:
adr r0, value
ldr r7, [r0]
svc 0

value: 
.word 1234
";

using var keystone = new Engine(Architecture.ARM, Mode.ARM) { ThrowOnError = true };


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

unicorn.MemMap(0, 2 * 1024 * 1024, Common.UC_PROT_ALL);
unicorn.MemWrite(0, encodedData.Buffer);
unicorn.RegWrite(Arm.UC_ARM_REG_SP, 0x200000);

unicorn.AddCodeHook((engine, address, size, data) => Console.WriteLine($"Address: {address:X}\tSize: {size}"),
    0, encodedData.Buffer.Length);

unicorn.AddInterruptHook(((unicorn1, i1, o) => unicorn1.EmuStop()));
unicorn.AddBlockHook(((unicorn1, l, i1, o) => Console.WriteLine("Block")), null, 0, encodedData.Buffer.Length);
unicorn.AddEventMemHook(((unicorn1, i1, l, i2, l1, o) =>
{
    Console.WriteLine("Event");
    return true;
}), Common.UC_HOOK_MEM_FETCH);

unicorn.EmuStart(0, encodedData.Buffer.Length, 0, 0);

Console.WriteLine($"Results: R0: {unicorn.RegRead(Arm.UC_ARM_REG_R0)}, R7: {unicorn.RegRead(Arm.UC_ARM_REG_R7)}");
