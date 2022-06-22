using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Code4Arm.ExecutionCore.Assembling;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Assembling.Models;
using Code4Arm.ExecutionCore.Execution;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Execution.Configuration;
using Code4Arm.ExecutionCore.Execution.FunctionSimulators.Stdio;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Code4Arm.ExecutionCore.Protocol.Events;
using Code4Arm.ExecutionCore.Protocol.Models;
using Code4Arm.ExecutionCore.Protocol.Requests;
using Code4Arm.Unicorn;
using Code4Arm.Unicorn.Abstractions.Enums;
using Code4Arm.Unicorn.Constants;
using ELFSharp.ELF.Sections;
using Gee.External.Capstone.Arm;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;
using Moq;
using Architecture = Code4Arm.Unicorn.Abstractions.Enums.Architecture;

namespace CoreExperiments;

public class Program
{
    private static readonly string ToolchainBin = Environment.OSVersion.Platform == PlatformID.Unix
        ? "/home/ondryaso/Projects/bp/gcc-arm-none-linux-gnueabihf/bin/"
        : @"C:\Users\ondry\Projects\bp-utils\gcc-arm-none-linux-gnueabihf\bin\";

    private static readonly string BinExt = Environment.OSVersion.Platform == PlatformID.Unix
        ? string.Empty
        : ".exe";

    public static readonly string Src = Environment.OSVersion.Platform == PlatformID.Unix
        ? "/home/ondryaso/Projects/bp/testasm/"
        : @"C:\Users\ondry\Projects\bp-test-vs-env\";

    private static LoggerFactory? _loggerFactory;

    public static async Task Main(string[] args)
    {
        if (Environment.OSVersion.Platform == PlatformID.Win32NT)
        {
            NativeLibrary.SetDllImportResolver(typeof(CapstoneArmDisassembler).Assembly,
                (name, assembly, path) =>
                    NativeLibrary.Load(
                        @"C:\Users\ondry\Projects\Capstone.NET\Gee.External.Capstone\runtimes\win-x86\native\capstone.dll",
                        assembly, path));
        }

        var asmOptions = new AssemblerOptions
        {
            GasPath = ToolchainBin + "arm-none-linux-gnueabihf-as" + BinExt,
            GasOptions = new[] { "-march=armv8.6-a+fp16+simd" }
        };
        var linkerOptions = new LinkerOptions
        {
            LdPath = ToolchainBin + "arm-none-linux-gnueabihf-ld" + BinExt
        };

        var loggerProvider = new ConsoleLoggerProvider(MakeLoggerOptions());
        _loggerFactory = new LoggerFactory(new[] { loggerProvider });

        var assembler = new Assembler(asmOptions, linkerOptions, _loggerFactory);
        assembler.UseFunctionSimulators(new[] { new Printf() });

        var proj = new DummyAsmMakeTarget("makeTarget",
            new DummyAsmFile("test.s") /*new DummyAsmFile("prog.s"), new DummyAsmFile("prog_a.s")*/);
        var res = await assembler.MakeProject(proj);

        if (res.State != MakeResultState.Successful)
        {
            await Console.Error.WriteLineAsync($"Error making makeTarget: {res.State.ToString()}.");

            if (res.State == MakeResultState.InvalidObjects)
                foreach (var r in res.InvalidObjects!)
                {
                    await Console.Error.WriteLineAsync(r.SourceFile.Name);
                    await Console.Error.WriteLineAsync(r.AssemblerErrors);
                    await Console.Error.WriteLineAsync();
                }
            else
                await Console.Error.WriteLineAsync(res.LinkerError);

            return;
        }

        var exe = res.Executable!;

        await TestExecution(exe);
        // TestUnicornFromExecutable(exe);

        exe.Dispose();
    }

    private static void TestUnicornFromExecutable(Executable exe)
    {
        var unicorn = new Unicorn(Architecture.Arm, EngineMode.Arm | EngineMode.LittleEndian);
        unicorn.CpuModel = Arm.Cpu.MAX;

        var p15 = new Arm.CoprocessorRegister
        {
            CoprocessorId = 15,
            Is64Bit = 0,
            SecurityState = 0,
            Crn = 1,
            Crm = 0,
            Opcode1 = 0,
            Opcode2 = 2
        };

        unicorn.RegRead(Arm.Register.CP_REG, ref p15);
        p15.Value |= 0xF00000;
        unicorn.RegWrite(Arm.Register.CP_REG, p15);
        unicorn.RegWrite(Arm.Register.FPEXC, 0x40000000);

        var (major, minor) = unicorn.Version;

        foreach (var segment in exe.Segments)
        {
            unicorn.MemMap(segment.StartAddress, segment.Size, segment.Permissions.ToUnicorn());
            if (segment.HasData)
                unicorn.MemWrite(segment.ContentsStartAddress, segment.GetData());
        }

        unicorn.MemMap(0x40000, 1024 * 1024, MemoryPermissions.Read | MemoryPermissions.Write);
        unicorn.RegWrite(Arm.Register.SP, 0x40000 + (1024 * 1024));

        const string initSymbol = "main";
        var initAddress = (exe.Elf.Sections.First(s => s.Type == SectionType.SymbolTable)
            as SymbolTable<uint>)?.Entries.First(s => s.Name == initSymbol)?.Value;

        if (initAddress == null)
            return;

        var capstone = new CapstoneArmDisassembler(ArmDisassembleMode.Arm | ArmDisassembleMode.V8);

        var pc = initAddress.Value;
        while (true)
        {
            if (pc >= 0xff000000u)
                pc = unicorn.RegRead<uint>(Arm.Register.LR);

            if (pc >= exe.TextSectionEndAddress)
                break;

            var d = capstone.Disassemble(unicorn.MemRead(pc, 4), pc, 1);
            var instr = d is { Length: not 0 } ? d[0] : null;

            Console.WriteLine($"Running at 0x{pc:X}: {instr?.Mnemonic} {instr?.Operand}");
            unicorn.EmuStart(pc, 0, 0, 1);
            pc = unicorn.RegRead<uint>(Arm.Register.PC);
        }

        Console.WriteLine("-- Finished --");
    }

    public static async Task TestExecution(Executable exe)
    {
        var services = new ServiceCollection();
        AddProtocolEventHandlers(services, typeof(IProtocolEvent));
        services.AddMediatR(typeof(Program));
        var provider = services.BuildServiceProvider();

        var execution = new ExecutionEngine(new ExecutionOptions { UseStrictMemoryAccess = true },
            new DebuggerOptions(), provider.GetRequiredService<IMediator>(),
            _loggerFactory!.CreateLogger<ExecutionEngine>());

        execution.DebugProvider.Initialize(new InitializeRequestArguments
        {
            ColumnsStartAt1 = true,
            LinesStartAt1 = true,
            Locale = "en-US",
            AdapterId = "plox",
            ClientId = "plox",
            ClientName = "Plox",
            PathFormat = PathFormat.Path
        });

        await execution.LoadExecutable(exe);
        await execution.InitLaunch(true, -1, false);

        await execution.CurrentExecutionTask!;

        Console.WriteLine("!! Finished !!");
        execution.Dispose();
    }

    public static void AddProtocolEventHandlers(IServiceCollection services, Type eventsAssembly)
    {
        var eventBase = typeof(IProtocolEvent);
        var eventTypes = eventsAssembly.Assembly.GetTypes().Where(t => t.IsAssignableTo(eventBase));

        var engineEventBase = typeof(EngineEvent<>);
        var requestHandlerBase = typeof(IRequestHandler<,>);
        var unit = typeof(Unit);
        var handlerBase = typeof(EngineEventRequestHandler<>);

        foreach (var eventType in eventTypes)
        {
            var engineEvent = engineEventBase.MakeGenericType(eventType);
            var iRequestHandlerType = requestHandlerBase.MakeGenericType(engineEvent, unit);
            var eeRequestHandlerType = handlerBase.MakeGenericType(eventType);
            services.AddTransient(iRequestHandlerType, eeRequestHandlerType);
        }
    }

    private static IOptionsMonitor<ConsoleLoggerOptions> MakeLoggerOptions()
    {
        var mock = new Mock<IOptionsMonitor<ConsoleLoggerOptions>>();
        mock.Setup(a => a.CurrentValue).Returns(new ConsoleLoggerOptions());

        return mock.Object;
    }
}

public class DummyAsmFile : IAsmFile
{
    public DummyAsmFile(string name)
    {
        Name = name;
    }

    public ValueTask<ILocatedFile> LocateAsync() => new ValueTask<ILocatedFile>(new DummyLocatedFile { File = this });

    public string Name { get; }
    public string ClientPath => this.LocateAsync().Result.FileSystemPath;
    public int Version => 0;
    public IAsmMakeTarget? Project { get; set; }
    public bool Equals(IAsmFile? other) => ReferenceEquals(other, this);

    private class DummyLocatedFile : ILocatedFile
    {
        public string FileSystemPath => Program.Src + File.Name;

        public int Version => File.Version;
        public IAsmFile File { get; init; } = null!;

        public void Dispose()
        {
        }
    }
}

public class DummyAsmMakeTarget : IAsmMakeTarget
{
    public List<DummyAsmFile> Files { get; }

    public DummyAsmMakeTarget(string name, params DummyAsmFile[] files)
    {
        Name = name;
        Files = new List<DummyAsmFile>(files);
        Files.ForEach(f => f.Project = this);
    }

    public string Name { get; }

    public IEnumerable<IAsmFile> GetFiles() => Files;

    public IAsmFile? GetFile(string name)
    {
        return Files.Find(f => f.Name == name);
    }
}

public class EngineEventRequestHandler<TEvent> : IRequestHandler<EngineEvent<TEvent>>
    where TEvent : IProtocolEvent
{
    private readonly string _eventName;

    public EngineEventRequestHandler()
    {
        var eventAttribute = typeof(TEvent).GetCustomAttribute<ProtocolEventAttribute>();

        if (eventAttribute == null)
            throw new ArgumentException(
                $"Cannot create an engine event request handler for unannotated type {typeof(TEvent).FullName}.");

        _eventName = eventAttribute.EventName;
    }

    public async Task<Unit> Handle(EngineEvent<TEvent> request, CancellationToken cancellationToken)
    {
        if (request.Event is OutputEvent outputEvent)
        {
            await Console.Error.WriteLineAsync($"OUTPUT: {outputEvent.Output}");

            return Unit.Value;
        }

        var json = JsonSerializer.Serialize(request.Event, new JsonSerializerOptions { WriteIndented = true });
        await Console.Error.WriteAsync($"EVENT {_eventName}: ");
        await Console.Error.WriteLineAsync(json);
        await Console.Error.WriteLineAsync();

        return Unit.Value;
    }
}
