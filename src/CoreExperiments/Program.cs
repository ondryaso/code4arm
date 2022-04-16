using System.Runtime.InteropServices;
using Code4Arm.ExecutionCore.Assembling;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution.FunctionSimulators;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Code4Arm.Unicorn;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Constants;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;
using Moq;
using Architecture = Code4Arm.Unicorn.Abstractions.Enums.Architecture;

namespace CoreExperiments;

public class Program
{
    public static async Task Main(string[] args)
    {
        var asmOptions = MakeAssemblerOptions();
        var linkerOptions = MakeLinkerOptions();
        var loggerProvider = new ConsoleLoggerProvider(MakeLoggerOptions());
        var loggerFactory = new LoggerFactory(new[] {loggerProvider});

        var assembler = new Assembler(asmOptions, linkerOptions, loggerFactory);
        assembler.UseFunctionSimulators(new[] {new Printf()});

        var proj = new DummyAsmProject("project", new DummyAsmFile("prog.s"), new DummyAsmFile("prog_a.s"));
        var res = await assembler.MakeProject(proj);

        if (res.State != MakeResultState.Successful)
        {
            Console.Error.WriteLine($"Error making project: {res.State.ToString()}.");

            if (res.State == MakeResultState.InvalidObjects)
            {
                foreach (var r in res.InvalidObjects!)
                {
                    Console.Error.WriteLine(r.SourceFile.Name);
                    Console.Error.WriteLine(r.AssemblerErrors);
                    Console.Error.WriteLine();
                }
            }
            else
            {
                Console.Error.WriteLine(res.LinkerError);
            }

            return;
        }

        var exe = res.Executable!;
        Emulate(exe);
        exe.Dispose();
    }

    private static void Emulate(Executable exe)
    {
        using IUnicorn unicorn =
            new Unicorn(Architecture.Arm, EngineMode.Arm | EngineMode.LittleEndian);

        byte[]? codeBytes = null;
        int s = 0;

        // Map ELF segments + trampoline
        foreach (var seg in exe.Segments)
        {
            unicorn.MemMap(seg.StartAddress, seg.Size, seg.Permissions.ToUnicorn());
            if (seg.HasData)
            {
                var data = seg.GetData();

                if (exe.TextSectionStartAddress >= seg.ContentsStartAddress &&
                    exe.TextSectionStartAddress < seg.ContentsEndAddress)
                {
                    var start = s = (int) (exe.TextSectionStartAddress - seg.ContentsStartAddress);
                    var end = (int) (exe.LastInstructionAddress - seg.ContentsStartAddress);
                    codeBytes = data[start..end];
                }

                unicorn.MemWrite(seg.ContentsStartAddress, seg.GetData());
            }
            else if (seg.IsTrampoline)
            {
                var jumpBackInstruction = new byte[] {0x1e, 0xff, 0x2f, 0xe1};
                for (var address = seg.ContentsStartAddress; address < seg.ContentsEndAddress; address += 4)
                {
                    unicorn.MemWrite(address, jumpBackInstruction);
                }
            }
        }

        ArmInstruction[]? disAsm = null;
        if (codeBytes != null)
        {
            using var cap = CapstoneDisassembler.CreateArmDisassembler(
                ArmDisassembleMode.LittleEndian | ArmDisassembleMode.V8);
            //disAsm = cap.Disassemble(codeBytes, exe.TextSectionStartAddress);
            disAsm = cap.Disassemble(exe.Segments[0].GetData()[s..], exe.TextSectionStartAddress);
        }

        // Add stack
        var stackMemoryStart = 0xe0000000;
        nuint stackSize = 2 * 4096;
        var stackPtrInitialValue = (uint) (stackMemoryStart + stackSize);
        unicorn.MemMap(stackMemoryStart, stackSize, MemoryPermissions.Read | MemoryPermissions.Write);
        unicorn.RegWrite(Arm.Register.SP, stackPtrInitialValue);

        // Hooks
        ulong pc = exe.EntryPoint;
        var shouldStop = false;

        unicorn.AddInterruptHook((engine, interrupt) =>
        {
            Console.WriteLine($"Interrupt {interrupt}.");
            engine.EmuStop();
            shouldStop = true;
        }, 0, ulong.MaxValue);

        unicorn.MemMap(0xfe000000, 4096, (engine, offset, size) => 69,
            (engine, offset, size, value) => Console.WriteLine($"MMIO write on {offset}: {value}"));

        unicorn.AddInvalidMemoryAccessHook((engine, type, address, size, value) =>
        {
            Console.WriteLine($"Invalid memory operation on {address}.");
            return false;
        }, MemoryHookType.FetchUnmapped, 0, ulong.MaxValue);
        
        var i = 0;

        unicorn.AddCodeHook((engine, start, size) =>
        {
            var instr = (int) (start - exe.TextSectionStartAddress) / 4;
            if (disAsm != null && disAsm.Length > instr && instr >= 0)
            {
                Console.WriteLine(
                    $"{i++}: #{instr} [{(pc):X}]: {disAsm[instr].Mnemonic} {disAsm[instr].Operand}");
            }
            else
            {
                Console.WriteLine($"{i++}: #? [{pc:X}]");
            }

            if (exe.FunctionSimulators?.TryGetValue((uint) start, out var sim) ?? false)
            {
                sim.FunctionSimulator.Run(engine);
            }
        }, 0, long.MaxValue);

        // Emulate
        try
        {
            //unicorn.EmuStart(pc, int.MaxValue, 0, 0);

            while (!shouldStop)
            {
                unicorn.EmuStart(pc, long.MaxValue, 0, 1);
                pc = unicorn.RegRead<uint>(Arm.Register.PC);
            }
        }
        catch (UnicornException e)
        {
            Console.WriteLine(e.Message);
        }

        // Free mapped ELF segments
        foreach (var seg in exe.Segments)
        {
            unicorn.MemUnmap(seg.StartAddress, seg.Size);
        }

        // Free stack
        unicorn.MemUnmap(stackMemoryStart, stackSize);

        // Close Unicorn
        unicorn.Dispose();
    }

    private static IOptionsSnapshot<AssemblerOptions> MakeAssemblerOptions()
    {
        var mock = new Mock<IOptionsSnapshot<AssemblerOptions>>();
        mock.Setup(a => a.Value).Returns(new AssemblerOptions()
        {
            GasPath =
                @"C:\Users\ondry\Projects\bp-utils\gcc-arm-none-linux-gnueabihf\bin\arm-none-linux-gnueabihf-as.exe"
        });
        return mock.Object;
    }

    private static IOptionsSnapshot<LinkerOptions> MakeLinkerOptions()
    {
        var mock = new Mock<IOptionsSnapshot<LinkerOptions>>();
        mock.Setup(a => a.Value).Returns(new LinkerOptions()
        {
            LdPath =
                @"C:\Users\ondry\Projects\bp-utils\gcc-arm-none-linux-gnueabihf\bin\arm-none-linux-gnueabihf-ld.exe"
        });
        return mock.Object;
    }

    private static IOptionsMonitor<ConsoleLoggerOptions> MakeLoggerOptions()
    {
        var mock = new Mock<IOptionsMonitor<ConsoleLoggerOptions>>();
        mock.Setup(a => a.CurrentValue).Returns(new ConsoleLoggerOptions() { });
        return mock.Object;
    }
}

public class DummyAsmFile : IAsmFile
{
    private class DummyLocatedFile : ILocatedFile
    {
        public void Dispose()
        {
        }

        public string FileSystemPath => @"C:\Users\ondry\Projects\bp-test-vs-env\" + this.File.Name;
        public int Version => this.File.Version;
        public IAsmFile File { get; init; } = null!;
    }

    public Task<ILocatedFile> LocateAsync()
    {
        return Task.FromResult((ILocatedFile) new DummyLocatedFile {File = this});
    }

    public DummyAsmFile(string name)
    {
        this.Name = name;
    }

    public string Name { get; }
    public int Version => 0;
    public IAsmProject? Project { get; set; }
}

public class DummyAsmProject : IAsmProject
{
    public string Name { get; }
    public List<DummyAsmFile> Files { get; }

    public DummyAsmProject(string name, params DummyAsmFile[] files)
    {
        this.Name = name;
        this.Files = new List<DummyAsmFile>(files);
        this.Files.ForEach(f => f.Project = this);
    }

    public IEnumerable<IAsmFile> GetFiles()
    {
        return this.Files;
    }

    public IAsmFile? GetFile(string name)
    {
        return this.Files.Find(f => f.Name == name);
    }
}