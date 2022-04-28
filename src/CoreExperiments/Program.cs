using Code4Arm.ExecutionCore.Assembling;
using Code4Arm.ExecutionCore.Assembling.Abstractions;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.FunctionSimulators;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.Unicorn;
using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Constants;
using Gee.External.Capstone;
using Gee.External.Capstone.Arm;
using MediatR;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;
using Moq;

namespace CoreExperiments;

public class Program
{
    public static async Task Main(string[] args)
    {
        var asmOptions = new AssemblerOptions()
        {
            GasPath = ToolchainBin + "arm-none-linux-gnueabihf-as" + BinExt
        };
        var linkerOptions = new LinkerOptions()
        {
            LdPath = ToolchainBin + "arm-none-linux-gnueabihf-ld" + BinExt
        };

        var loggerProvider = new ConsoleLoggerProvider(MakeLoggerOptions());
        var loggerFactory = new LoggerFactory(new[] { loggerProvider });

        var assembler = new Assembler(asmOptions, linkerOptions, loggerFactory);
        assembler.UseFunctionSimulators(new[] { new Printf() });

        var proj = new DummyAsmMakeTarget("makeTarget", new DummyAsmFile("test.s"));
        var res = await assembler.MakeProject(proj);

        if (res.State != MakeResultState.Successful)
        {
            Console.Error.WriteLine($"Error making makeTarget: {res.State.ToString()}.");

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
        await Emulate(exe, loggerFactory.CreateLogger<ExecutionEngine>());
        exe.Dispose();
    }

    private static async Task Emulate(Executable exe, ILogger<ExecutionEngine> logger)
    {
        var execution = new ExecutionEngine(new ExecutionOptions() { UseStrictMemoryAccess = true },
            Mock.Of<IMediator>(),
            logger, logger);
        await execution.LoadExecutable(exe);

        while (true)
        {
            await execution.Launch(true);
            Console.WriteLine(execution.Engine.RegRead<uint>(Arm.Register.R0));
        }
    }

    private static void EmulateOld(Executable exe, ILogger<ExecutionEngine> logger)
    {
        var execution = new ExecutionEngine(new ExecutionOptions() { UseStrictMemoryAccess = true },
            Mock.Of<IMediator>(), logger, logger);
        execution.LoadExecutable(exe);
        execution.InitMemoryFromExecutable();

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
            Console.WriteLine($"Invalid memory operation on {address:x8}.");

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

    private static IOptionsMonitor<ConsoleLoggerOptions> MakeLoggerOptions()
    {
        var mock = new Mock<IOptionsMonitor<ConsoleLoggerOptions>>();
        mock.Setup(a => a.CurrentValue).Returns(new ConsoleLoggerOptions());

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
    public IAsmMakeTarget? Project { get; set; }
    public bool Equals(IAsmFile? other) => ReferenceEquals(other, this);
}

public class DummyAsmMakeTarget : IAsmMakeTarget
{
    public string Name { get; }
    public List<DummyAsmFile> Files { get; }

    public DummyAsmMakeTarget(string name, params DummyAsmFile[] files)
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
