using Code4Arm.ExecutionCore.Assembling;
using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Execution.FunctionSimulators;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Logging.Console;
using Microsoft.Extensions.Options;
using Moq;

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
        assembler.UseFunctionSimulators(new []{new Printf()});
        
        var proj = new DummyAsmProject("project", new DummyAsmFile("prog20a.s"), new DummyAsmFile("prog21b.s"));
        var res = await assembler.MakeProject(proj);
        
        return;
    }

    private static IOptionsSnapshot<AssemblerOptions> MakeAssemblerOptions()
    {
        var mock = new Mock<IOptionsSnapshot<AssemblerOptions>>();
        mock.Setup(a => a.Value).Returns(new AssemblerOptions()
        {
            GasPath = @"/home/ondryaso/Projects/bp/gcc-arm-none-linux-gnueabihf/bin/arm-none-linux-gnueabihf-as"
        });
        return mock.Object;
    }

    private static IOptionsSnapshot<LinkerOptions> MakeLinkerOptions()
    {
        var mock = new Mock<IOptionsSnapshot<LinkerOptions>>();
        mock.Setup(a => a.Value).Returns(new LinkerOptions()
        {
            LdPath = @"/home/ondryaso/Projects/bp/gcc-arm-none-linux-gnueabihf/bin/arm-none-linux-gnueabihf-ld"
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

        public string FileSystemPath => "/home/ondryaso/Projects/bp/testasm/" + this.File.Name;
        public int Version => this.File.Version;
        public IAsmFile File { get; init; } = null!;
    }

    public Task<ILocatedFile> LocateAsync()
    {
        return Task.FromResult((ILocatedFile)new DummyLocatedFile { File = this });
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
