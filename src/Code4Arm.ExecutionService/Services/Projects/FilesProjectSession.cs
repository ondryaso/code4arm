// FilesProjectSession.cs
// Author: Ondřej Ondryáš

using Code4Arm.ExecutionCore.Assembling.Configuration;
using Code4Arm.ExecutionCore.Execution.Abstractions;
using Code4Arm.ExecutionCore.Files.Abstractions;
using Code4Arm.ExecutionService.Files;
using Microsoft.Extensions.Options;

namespace Code4Arm.ExecutionService.Services.Projects;

public class FilesProjectSession : BaseProjectSession
{
    private readonly Dictionary<string, LocalAsmFile> _files = new();
    private readonly object _loadingLocker = new();

    public FilesProjectSession(IEnumerable<string> files, string? name,
        AssemblerOptions assemblerOptions, LinkerOptions linkerOptions,
        IFunctionSimulator[] simulators, ILoggerFactory loggerFactory)
        : base(assemblerOptions, linkerOptions, simulators, loggerFactory)
    {
        Name = name ?? Guid.NewGuid().ToString();
        this.LoadFiles(files);
    }

    public void LoadFiles(IEnumerable<string> files)
    {
        lock (_loadingLocker)
        {
            _files.Clear();
            foreach (var file in files)
            {
                var asmFile = new LocalAsmFile(file, null, this) { LastBuiltVersion = -1 };
                _files.Add(file, asmFile);
            }
        }
    }

    public override string Name { get; }
    public override IEnumerable<IAsmFile> GetFiles() => throw new NotImplementedException();

    public override IAsmFile? GetFile(string name) => throw new NotImplementedException();

    public override bool Dirty
    {
        get
        {
            lock (_loadingLocker)
            {
                return _files.Values.Any(f => f.LastBuiltVersion != f.Version);
            }
        }
    }
}
