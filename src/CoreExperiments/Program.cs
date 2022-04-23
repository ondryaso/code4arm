using System.Reflection;
using System.Runtime.InteropServices;
using Code4Arm.ExecutionCore.Assembling;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Dwarf;
using Code4Arm.ExecutionCore.Execution;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.FunctionSimulators;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Code4Arm.Unicorn;
using Code4Arm.Unicorn.Abstractions;
using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Constants;
using ELFSharp.ELF;
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
        var loggerFactory = new LoggerFactory(new[] { loggerProvider });

        var assembler = new Assembler(asmOptions, linkerOptions, loggerFactory);
        assembler.UseFunctionSimulators(new[] { new Printf() });

        var proj = new DummyAsmProject("project", new DummyAsmFile("prog20a.s"), new DummyAsmFile("prog21b.s"));
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
        var elf =
            typeof(Executable).GetField("_elf", BindingFlags.Instance | BindingFlags.NonPublic)
                              ?.GetValue(exe) as ELF<uint>;

        var dsp = new DwarfLineAddressResolver(elf);
        var a = dsp.GetSourceLine(0x10078, out _);
        var b = dsp.GetSourceLine(0x10079, out var disp);
        var c = dsp.GetSourceLine(0x10098, out _);
        var d = dsp.GetSourceLine(0x100e4, out _);
        var e = dsp.GetSourceLine(0x100e8, out _);
        var f = dsp.GetSourceLine(0x100ec, out _);
        
        var h = dsp.GetAddress(a.File.Name, (int)a.Line);
        var i = dsp.GetAddress(c.File.Name, (int)c.Line);
        var j = dsp.GetAddress(d.File.Name, (int)d.Line);
        var k = dsp.GetAddress(e.File.Name, (int)e.Line);
        var l = dsp.GetAddress(f.File.Name, (int)f.Line);
        
        Emulate(exe);
        exe.Dispose();
    }

    private static void Emulate(Executable exe)
    {
        var execution = new ExecutionEngine(new ExecutionOptions() { UseStrictMemoryAccess = true });
        execution.LoadExecutable(exe);

        var unicorn = execution.Engine;

        byte[] codeBytes = new byte[exe.TextSectionEndAddress - exe.TextSectionStartAddress];
        unicorn.MemRead(exe.TextSectionStartAddress, codeBytes);
        var s = 0;

        // Get disassembly
        foreach (var seg in exe.Segments)
        {
            if (exe.TextSectionStartAddress >= seg.ContentsStartAddress &&
                exe.TextSectionStartAddress < seg.ContentsEndAddress)
            {
                s = (int)(exe.TextSectionStartAddress - seg.ContentsStartAddress);

                break;
            }
        }

        ArmInstruction[]? disAsm = null;
        using var cap = CapstoneDisassembler.CreateArmDisassembler(
            ArmDisassembleMode.LittleEndian | ArmDisassembleMode.V8);
        //disAsm = cap.Disassemble(codeBytes, exe.TextSectionStartAddress);
        disAsm = cap.Disassemble(exe.Segments[0].GetData()[s..], exe.TextSectionStartAddress);

        execution.Engine.RegWrite(Arm.Register.SP, execution.StackTopAddress);

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

        var codeHookRegistration = unicorn.AddCodeHook((engine, start, size) =>
        {
            var instr = (int)(start - exe.TextSectionStartAddress) / 4;
            if (disAsm != null && disAsm.Length > instr && instr >= 0)
            {
                Console.WriteLine(
                    $"{i++}: #{instr} [{(start):X}]: {disAsm[instr].Mnemonic} {disAsm[instr].Operand}");
            }
            else
            {
                Console.WriteLine($"{i++}: #? [{start:X}]");
            }
        }, exe.TextSectionStartAddress, exe.TextSectionEndAddress);

        var trampolineHookRegistration = unicorn.AddCodeHook((engine, start, size) =>
        {
            if (exe.FunctionSimulators?.TryGetValue((uint)start, out var sim) ?? false)
            {
                sim.FunctionSimulator.Run(engine);
            }
        }, 0xff000000, 0xffffffff);

        // Emulate
        try
        {
            unicorn.EmuStart(pc, exe.LastInstructionAddress, 0, 0);

            /* while (!shouldStop)
             {
                 unicorn.EmuStart(pc, pc +4, 0, 0);
                 pc = unicorn.RegRead<uint>(Arm.Register.PC);
             }*/
        }
        catch (UnicornException e)
        {
            Console.WriteLine(e.Message);
        }

        execution.Dispose();
    }

    private static readonly string ToolchainBin = Environment.OSVersion.Platform == PlatformID.Unix
        ? "/home/ondryaso/Projects/bp/gcc-arm-none-linux-gnueabihf/bin/"
        : @"C:\Users\ondry\Projects\bp-utils\gcc-arm-none-linux-gnueabihf\bin\";

    private static readonly string BinExt = Environment.OSVersion.Platform == PlatformID.Unix
        ? string.Empty
        : ".exe";

    public static readonly string Src = Environment.OSVersion.Platform == PlatformID.Unix
        ? "/home/ondryaso/Projects/bp/testasm/"
        : @"C:\Users\ondry\Projects\bp-test-vs-env\";

    private static IOptionsSnapshot<AssemblerOptions> MakeAssemblerOptions()
    {
        var mock = new Mock<IOptionsSnapshot<AssemblerOptions>>();
        mock.Setup(a => a.Value).Returns(new AssemblerOptions()
        {
            GasPath = ToolchainBin + "arm-none-linux-gnueabihf-as" + BinExt
        });

        return mock.Object;
    }

    private static IOptionsSnapshot<LinkerOptions> MakeLinkerOptions()
    {
        var mock = new Mock<IOptionsSnapshot<LinkerOptions>>();
        mock.Setup(a => a.Value).Returns(new LinkerOptions()
        {
            LdPath = ToolchainBin + "arm-none-linux-gnueabihf-ld" + BinExt
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

        public string FileSystemPath => Program.Src + this.File.Name;

        public int Version => this.File.Version;
        public IAsmFile File { get; init; } = null!;
    }

    public ValueTask<ILocatedFile> LocateAsync()
    {
        return new ValueTask<ILocatedFile>(new DummyLocatedFile { File = this });
    }

    public DummyAsmFile(string name)
    {
        this.Name = name;
    }

    public string Name { get; }
    public string ClientPath => this.LocateAsync().Result.FileSystemPath;
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
